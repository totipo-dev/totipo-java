package org.totipo.format;

import org.totipo.VaultState;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.Flow;
import java.util.concurrent.ForkJoinPool;

/** Bounded replay-latest publisher. Each subscription serializes its own callbacks. */
final class ApplicationStates implements Flow.Publisher<VaultState> {
    private final Set<Subscription> subscribers = new HashSet<>();
    private volatile ApplicationSession.State latest;
    private boolean closed;
    private Throwable failure;
    ApplicationStates(ApplicationSession.State initial) { latest = initial; }
    ApplicationSession.State current() { return latest; }
    synchronized void emit(ApplicationSession.State state) {
        if (closed || state.sequence <= latest.sequence) return;
        latest = state;
        for (var subscriber : subscribers) subscriber.signal();
    }
    synchronized void terminate(Throwable cause) {
        if (closed) return;
        failure = cause;
        closed = true;
        for (var subscriber : Set.copyOf(subscribers)) subscriber.signal();
    }
    @Override public void subscribe(Flow.Subscriber<? super VaultState> subscriber) {
        Objects.requireNonNull(subscriber);
        var subscription = new Subscription(subscriber);
        synchronized (this) { subscribers.add(subscription); }
        // Subscribe is always first, even when demand or cancellation is reentrant.
        try { subscriber.onSubscribe(subscription); }
        catch (Throwable rejected) { subscription.cancel(); }
        synchronized (this) { subscription.started = true; subscription.signal(); }
    }
    private final class Subscription implements Flow.Subscription, Runnable {
        private final Flow.Subscriber<? super VaultState> subscriber;
        private long demand, delivered = -1;
        private boolean started, scheduled, ended;
        private Throwable error;
        Subscription(Flow.Subscriber<? super VaultState> subscriber) { this.subscriber = subscriber; }
        @Override public void request(long count) {
            synchronized (ApplicationStates.this) {
                if (ended || closed) return;
                if (count <= 0) error = new IllegalArgumentException("Positive demand required");
                else { long sum = demand + count; demand = sum < 0 ? Long.MAX_VALUE : sum; }
                signal();
            }
        }
        @Override public void cancel() {
            synchronized (ApplicationStates.this) { ended = true; subscribers.remove(this); }
        }
        // Called only under the publisher monitor; at most one scheduled worker per subscriber.
        void signal() {
            if (!started || scheduled || ended) return;
            scheduled = true;
            ForkJoinPool.commonPool().execute(this);
        }
        @Override public void run() {
            while (true) {
                ApplicationSession.State next;
                Throwable failure;
                boolean terminal;
                synchronized (ApplicationStates.this) {
                    if (ended) { scheduled = false; return; }
                    failure = error == null ? ApplicationStates.this.failure : error;
                    terminal = closed || failure != null;
                    if (terminal) { ended = true; subscribers.remove(this); next = null; }
                    else if (demand > 0 && latest.sequence > delivered) {
                        next = latest; delivered = next.sequence;
                        if (demand != Long.MAX_VALUE) demand--;
                    } else { scheduled = false; return; }
                }
                try {
                    if (terminal) {
                        if (failure != null) subscriber.onError(failure); else subscriber.onComplete();
                        return;
                    }
                    subscriber.onNext(next);
                } catch (Throwable rejected) { cancel(); return; }
            }
        }
    }
}
