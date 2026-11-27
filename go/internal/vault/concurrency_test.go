package vault

import (
	"context"
	"fmt"
	"sync"
	"testing"
)

// TestConcurrentOpsDuringRotation runs writers, readers, listers and
// fingerprinters while the DEK and master key rotate (run with -race).
// Every value written must stay readable and the chain must verify.
func TestConcurrentOpsDuringRotation(t *testing.T) {
	ctx := context.Background()
	v, _ := newVault(t, allowAllPolicy)
	const workers, perWorker = 6, 15
	for w := 0; w < workers; w++ {
		set(t, v, "c", fmt.Sprintf("w%d-seed", w), "seed")
	}

	var wg sync.WaitGroup
	errs := make(chan error, 1024)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				name := fmt.Sprintf("w%d-%d", w, i)
				if err := v.SetSecret(ctx, SetSecretRequest{Name: name, Namespace: "c", Agent: "writer",
					Value: []byte("val-" + name)}); err != nil {
					errs <- err
					return
				}
				err := v.Lease(ctx, LeaseRequest{Name: name, Namespace: "c", Agent: "reader", Purpose: "p"},
					func(b []byte) error {
						if string(b) != "val-"+name {
							return fmt.Errorf("read %q for %s", b, name)
						}
						return nil
					})
				if err != nil {
					errs <- err
					return
				}
				if _, err := v.Fingerprint(ctx, "c", name, 0); err != nil {
					errs <- err
					return
				}
				if _, err := v.ListSecrets(ctx, ListRequest{Namespace: "c", Agent: "lister"}); err != nil {
					errs <- err
					return
				}
			}
		}(w)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 3; i++ {
			if err := v.RotateDEK(ctx); err != nil {
				errs <- err
				return
			}
			if err := v.RotateMaster(ctx); err != nil {
				errs <- err
				return
			}
			if _, err := v.Export(ctx); err != nil {
				errs <- err
				return
			}
		}
	}()
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if v.KeyEpoch() != 7 {
		t.Fatalf("epoch %d, want 7", v.KeyEpoch())
	}
	for w := 0; w < workers; w++ {
		for i := 0; i < perWorker; i++ {
			name := fmt.Sprintf("w%d-%d", w, i)
			if got, err := get(t, v, "c", name, 0); err != nil || got != "val-"+name {
				t.Fatalf("%s = %q, %v", name, got, err)
			}
		}
	}
	mustVerify(t, v)
}
