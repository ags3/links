package processor

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"bitbucket.it.keysight.com/isgappsec/wap-installer/pkg/config"
	"bitbucket.it.keysight.com/isgappsec/wap-installer/pkg/container"
)

type actionType string
type actionStatus string

const (
	loadAction actionType = "load"
	pushAction actionType = "push"
)

const (
	preparingAction    actionStatus = "preparing"
	successfulAction   actionStatus = "successful"
	unsuccessfulAction actionStatus = "unsuccessful"
)

type actionMessage struct {
	err       error
	image     string
	worker    int
	actType   actionType
	actStatus actionStatus
}

// Represents an action to be done on a container image (loading or pushing).
type action struct {
	cb      func(context.Context, int, *container.ImageRef, chan<- *actionMessage) error
	actType actionType
}

type workerData struct {
	worker int
	workCh <-chan *container.ImageRef
	msgCh  chan<- *actionMessage
	action *action
}

// An ImageProcessor is used to process container images.
type ImageProcessor struct {
	handler container.ImageHandler
	cfg     *config.Config
}

// NewImageProcessor creates a new container images processor.
func NewImageProcessor(cfg *config.Config) (*ImageProcessor, error) {
	imageHandler, err := container.NewImageHandler(cfg.Install.VerifyImageSignatures)
	if err != nil {
		return nil, nil
	}
	return &ImageProcessor{handler: imageHandler, cfg: cfg}, nil
}

// ProcessImages is used to process the given list of images.
func (p *ImageProcessor) ProcessImages(ctx context.Context, imageRefs []*container.ImageRef) error {
	var imageRefsToProcess []*container.ImageRef
	for _, imageRef := range imageRefs {
		if imageRef.NeedsPush(p.cfg) {
			imageRefsToProcess = append(imageRefsToProcess, imageRef)
		}
	}
	if len(imageRefsToProcess) == 0 {
		return nil
	}

	// Load and tag the images.
	loadAction := action{cb: p.loadAndTagImage, actType: loadAction}
	err := p.processImages(ctx, imageRefsToProcess, &loadAction, p.cfg.Install.NumLoadWorkers)
	if err != nil {
		return err
	}

	// Push the images to the private registry.
	pushAction := action{cb: p.pushImage, actType: pushAction}
	return p.processImages(ctx, imageRefsToProcess, &pushAction, p.cfg.Install.NumPushWorkers)
}

func (p *ImageProcessor) processImages(ctx context.Context, imageRefs []*container.ImageRef, action *action, numWorkers uint) error {
	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	workCh := make(chan *container.ImageRef, numWorkers*10)
	msgCh := make(chan *actionMessage, numWorkers*10)
	var wg sync.WaitGroup

	for i := 0; i < int(numWorkers); i++ {
		wg.Add(1)
		workData := workerData{
			worker: i + 1,
			workCh: workCh,
			msgCh:  msgCh,
			action: action,
		}
		go p.processImagesWorker(workerCtx, cancel, &wg, &workData)
	}

	go p.sendImagesToWorkers(workerCtx, workCh, imageRefs)

	go func() {
		wg.Wait()
		close(msgCh)
	}()

	return p.processMessages(msgCh)
}

func (p *ImageProcessor) processMessages(msgCh <-chan *actionMessage) error {
	var firstErr error

	for msg := range msgCh {
		p.logMessage(msg)
		if msg.err != nil && firstErr == nil {
			firstErr = msg.err
		}
	}
	return firstErr
}

func (p *ImageProcessor) logMessage(msg *actionMessage) {
	logMsg := fmt.Sprintf("%s %s image [%s], worker [%d]\n",
		strings.Title(string(msg.actStatus)), msg.actType, msg.image, msg.worker)
	if msg.err == nil {
		fmt.Printf("[INFO] " + logMsg)
	} else {
		fmt.Printf("[ERROR] " + logMsg)
		fmt.Printf("[ERROR] %v\n", msg.err)
	}
}

// This is the producer goroutine, which sends the image references to consumer goroutines
// (workers).
func (p *ImageProcessor) sendImagesToWorkers(ctx context.Context, workCh chan<- *container.ImageRef, imageRefs []*container.ImageRef) {
	for _, imageRef := range imageRefs {
		select {
		case <-ctx.Done():
			return
		case workCh <- imageRef:
		}
	}
	close(workCh)
}

// This is the consumer goroutine: it receives image references from the producer goroutine and
// executes actions on them.
// Messages produced during the actions execution are pushed into the messages channel, from which
// they will processed (logged) by the main goroutine.
func (p *ImageProcessor) processImagesWorker(ctx context.Context, cancel context.CancelFunc, wg *sync.WaitGroup, wd *workerData) {
	defer wg.Done()
	for {
		select {
		case <-ctx.Done():
			err := ctx.Err()
			if err != nil {
				wd.msgCh <- &actionMessage{
					err:       err,
					worker:    wd.worker,
					actType:   wd.action.actType,
					actStatus: unsuccessfulAction,
				}
			}
			return
		case imageRef, ok := <-wd.workCh:
			if !ok {
				return
			}

			if err := ctx.Err(); err != nil {
				wd.msgCh <- &actionMessage{
					err:       err,
					image:     imageRef.FullName(),
					worker:    wd.worker,
					actType:   wd.action.actType,
					actStatus: unsuccessfulAction,
				}
				return
			}

			// Execute the action. If we get an error, we finish this worker and we
			// cancel the context in order to signal other workers to stop.
			if err := wd.action.cb(ctx, wd.worker, imageRef, wd.msgCh); err != nil {
				cancel()
				return
			}
		}
	}
}

func (p *ImageProcessor) loadAndTagImage(ctx context.Context, worker int, imageRef *container.ImageRef, msgCh chan<- *actionMessage) error {
	var err error
	msgCh <- &actionMessage{
		err:       err,
		image:     imageRef.FullName(),
		worker:    worker,
		actType:   loadAction,
		actStatus: preparingAction,
	}
	time.Sleep(3 * time.Second)
	msgCh <- &actionMessage{
		err:       err,
		image:     imageRef.FullName(),
		worker:    worker,
		actType:   loadAction,
		actStatus: successfulAction,
	}
	return err
}

func (p *ImageProcessor) pushImage(ctx context.Context, worker int, imageRef *container.ImageRef, msgCh chan<- *actionMessage) error {
	var err error
	image := imageRef.FullNameForRegistry(p.cfg.PrivateRegistry.Name)
	msgCh <- &actionMessage{
		err:       err,
		image:     image,
		worker:    worker,
		actType:   pushAction,
		actStatus: preparingAction,
	}
	time.Sleep(3 * time.Second)
	msgCh <- &actionMessage{
		err:       err,
		image:     image,
		worker:    worker,
		actType:   pushAction,
		actStatus: successfulAction,
	}
	return err
}
