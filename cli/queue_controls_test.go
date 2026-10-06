package main

import (
	"fmt"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

func TestQueueCanPauseAndRemoveIndividualQuestion(t *testing.T) {
	useDeadServices(t)
	m := newKeyModel(t)
	m.queue = []string{"first question", "second question"}
	nm, _ := m.dispatchInput("/queue remove 1")
	m = nm.(model)
	if len(m.queue) != 1 || m.queue[0] != "second question" {
		t.Fatal("queue removal changed wrong questions")
	}
	nm, _ = m.dispatchInput("/queue pause")
	m = nm.(model)
	nm, _ = m.Update(dequeueMsg{})
	m = nm.(model)
	if len(m.queue) != 1 {
		t.Fatal("paused queue ran a question")
	}
}

func TestForcedRagDispatchRespectsQueueBound(t *testing.T) {
	useDeadServices(t)
	m := newKeyModel(t)
	m.working = true
	m.queue = make([]string, maxQueueItems)
	nm, _ := m.dispatchInput("/rag research question")
	if len(nm.(model).queue) != maxQueueItems {
		t.Fatal("forced retrieval bypassed queue cap")
	}
}

func TestQueueEditMovesQuestionToDraftWithoutSubmitting(t *testing.T) {
	useDeadServices(t)
	m := newKeyModel(t)
	m.queue = []string{"queued question"}
	nm, _ := m.dispatchInput("/queue edit 1")
	m = nm.(model)
	if len(m.queue) != 0 || m.ta.Value() != "queued question" || m.working {
		t.Fatal("editing submitted or lost queued text")
	}
}

func TestQueueBoundDoesNotDiscardRejectedDraft(t *testing.T) {
	useDeadServices(t)
	m := newKeyModel(t)
	m.working = true
	for i := 0; i < 64; i++ {
		m.setDraft("question " + strings.Repeat("x", 1024))
		nm, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
		m = nm.(model)
	}
	if len(m.queue) > 16 || m.ta.Value() == "" {
		t.Fatal("queue did not bound input or discarded the rejected draft")
	}
}

func TestQueueStopsAfterErrorsAndPreservesQuestions(t *testing.T) {
	useDeadServices(t)
	m := newKeyModel(t)
	m.working = true
	m.queue = []string{"next question"}
	nm, _ := m.Update(errMsg{err: fmt.Errorf("temporary failure")})
	m = nm.(model)
	nm, _ = m.Update(dequeueMsg{})
	m = nm.(model)
	if len(m.queue) != 1 || m.working {
		t.Fatal("failed turn started the next question")
	}
}

func TestEscapeCancellationPausesQueueBeforeLateCompletion(t *testing.T) {
	useDeadServices(t)
	m := newKeyModel(t)
	m.working = true
	m.turnStart = time.Now()
	m.pendingQ = "running question"
	m.queue = []string{"next question"}
	canceled := false
	m.cancel = func() { canceled = true }
	nm, _ := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = nm.(model)
	pausedBeforeCompletion := m.queuePaused
	nm, _ = m.Update(streamDoneMsg{full: "completed answer"})
	nm, _ = nm.(model).Update(dequeueMsg{})
	m = nm.(model)
	if !canceled || !pausedBeforeCompletion || !m.queuePaused || len(m.queue) != 1 || m.working {
		t.Fatalf("late completion resumed a canceled queue: pausedBefore=%v paused=%v queued=%d working=%v", pausedBeforeCompletion, m.queuePaused, len(m.queue), m.working)
	}
}

func TestRejectedQueuedTurnPausesAndPreservesItsDraft(t *testing.T) {
	useDeadServices(t)
	for _, rejected := range []string{"/ask", "/generate"} {
		t.Run(rejected, func(t *testing.T) {
			m := newKeyModel(t)
			m.queue = []string{rejected, "next question"}
			nm, _ := m.Update(dequeueMsg{})
			m = nm.(model)
			if !m.queuePaused || m.working || len(m.queue) != 2 || m.queue[0] != rejected {
				t.Fatalf("rejected queued turn was discarded or left ready: %+v, paused=%v", m.queue, m.queuePaused)
			}
			nm, _ = m.Update(dequeueMsg{})
			if len(nm.(model).queue) != 2 {
				t.Fatal("paused rejected queue ran another turn")
			}
		})
	}
}
