// The sockets of the web wallet.
//
// A browser gives a page no TCP. The wallet's module therefore keeps its
// connections at the gateway (web/gateway) and reaches them over one
// WebSocket: every message is one call (connect, send, receive, close, look a
// name up), every answer its result. To the rest of the program such a
// connection is an ordinary socket: it has a descriptor, and the C library's
// recv, send, shutdown, close and the calls that ask a socket about itself are
// taken over here for those descriptors (the linker's --wrap) and left alone
// for every other.
//
// The descriptors are numbers from FLY_BASE up, which the module's own table
// of files never reaches. One descriptor may be held twice (fly_dup): the
// network code reads on one thread and writes on another.
//
// The WebSocket belongs to the thread that runs the module's events; its
// answers arrive there. A call from that thread would wait for an answer only
// it can deliver, so it is refused (EDEADLK); every other thread waits. When
// the WebSocket is lost every waiting call fails and every connection is dead:
// the gateway has dropped them too.
//
// Nothing here reads what is carried.
#include <emscripten/emscripten.h>
#include <emscripten/threading.h>
#include <emscripten/websocket.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <unistd.h>

#define FLY_BASE 1000000
#define FLY_SLOTS 64
#define FLY_MAX_RECV (1u << 20)
#define FLY_MAX_SEND (1u << 18)
#define FLY_MAX_NAME 253
#define FLY_URL 256
#define FLY_CALL_MS 60000u
#define FLY_SLICE_MS 500.0
// a connection to the gateway that is neither made nor refused in this time is given up
#define FLY_OPENING_MS 10000.0

enum { OP_OPEN = 1, OP_SEND = 2, OP_RECV = 3, OP_CLOSE = 4, OP_RESOLVE = 5 };
// what the gateway says went wrong, in its own numbers
enum { G_REFUSED = 1, G_RESET = 2, G_TIMED_OUT = 3, G_UNREACHABLE = 4, G_NOT_ALLOWED = 5, G_AGAIN = 6, G_BAD_HANDLE = 7, G_TOO_MANY = 8, G_PIPE = 9, G_INVALID = 10 };

typedef struct Call {
  struct Call *next;
  uint32_t id;
  _Atomic uint32_t done;
  int32_t ret;
  int32_t code;
  uint8_t *data;
  uint32_t len;
} Call;

typedef struct Slot {
  int refs;         // 0: free
  int32_t handle;   // the gateway's name for the connection
  int alive;        // 0 once closed here or lost with the WebSocket
  int lost;         // lost with the WebSocket rather than closed here
  uint32_t recv_ms; // 0: wait as long as it takes
  struct sockaddr_in peer;
} Slot;

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static EMSCRIPTEN_WEBSOCKET_T ws;    // 0: none
static EMSCRIPTEN_WEBSOCKET_T stale; // a lost one, deleted before the next is made
static int state;                    // 0 none, 1 connecting, 2 open
static uintptr_t attempt;            // which WebSocket the events are taken from
static double attempt_began;         // when it was begun
static uint32_t next_id = 1;
static Call *pending;
static Slot slots[FLY_SLOTS];

static uint32_t rd32(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }
static void wr32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24); }

static int os_error(int32_t code) {
  switch (code) {
    case G_REFUSED: return ECONNREFUSED;
    case G_RESET: return ECONNRESET;
    case G_TIMED_OUT: return ETIMEDOUT;
    case G_UNREACHABLE: return EHOSTUNREACH;
    case G_NOT_ALLOWED: return EACCES;
    case G_AGAIN: return EAGAIN;
    case G_BAD_HANDLE: return ECONNRESET;
    case G_TOO_MANY: return EMFILE;
    case G_PIPE: return EPIPE;
    default: return EINVAL;
  }
}

// with the lock held
static Call *unlink_call(uint32_t id) {
  Call **at = &pending;
  while (*at) {
    if ((*at)->id == id) {
      Call *found = *at;
      *at = found->next;
      found->next = NULL;
      return found;
    }
    at = &(*at)->next;
  }
  return NULL;
}

// with the lock held: the WebSocket is gone, and all it carried with it
static void lost_locked(void) {
  if (ws) stale = ws;
  ws = 0;
  state = 0;
  for (int i = 0; i < FLY_SLOTS; i++) {
    if (slots[i].refs > 0 && slots[i].alive) {
      slots[i].alive = 0;
      slots[i].lost = 1;
    }
  }
  while (pending) {
    Call *c = pending;
    pending = c->next;
    c->next = NULL;
    c->ret = -1;
    c->code = G_RESET;
    atomic_store(&c->done, 1);
    emscripten_futex_wake(&c->done, 1);
  }
}

static bool on_open(int type, const EmscriptenWebSocketOpenEvent *event, void *user) {
  (void)type; (void)event;
  pthread_mutex_lock(&lock);
  if ((uintptr_t)user == attempt && state == 1) state = 2;
  pthread_mutex_unlock(&lock);
  return true;
}

static bool on_gone(uintptr_t which) {
  pthread_mutex_lock(&lock);
  if (which == attempt && state != 0) lost_locked();
  pthread_mutex_unlock(&lock);
  return true;
}
static bool on_close(int type, const EmscriptenWebSocketCloseEvent *event, void *user) { (void)type; (void)event; return on_gone((uintptr_t)user); }
static bool on_error(int type, const EmscriptenWebSocketErrorEvent *event, void *user) { (void)type; (void)event; return on_gone((uintptr_t)user); }

static bool on_message(int type, const EmscriptenWebSocketMessageEvent *event, void *user) {
  (void)type;
  if (event->isText || event->numBytes < 12) return true;
  uint32_t extra = event->numBytes - 12;
  uint8_t *copy = NULL;
  if (extra > 0) {
    copy = (uint8_t *)malloc(extra);
    if (!copy) return true;
    memcpy(copy, event->data + 12, extra);
  }
  pthread_mutex_lock(&lock);
  Call *c = (uintptr_t)user == attempt ? unlink_call(rd32(event->data)) : NULL;
  if (c) {
    c->ret = (int32_t)rd32(event->data + 4);
    c->code = (int32_t)rd32(event->data + 8);
    c->data = copy;
    c->len = extra;
    copy = NULL;
    atomic_store(&c->done, 1);
    emscripten_futex_wake(&c->done, 1);
  }
  pthread_mutex_unlock(&lock);
  free(copy);
  return true;
}

// Start connecting to the gateway at `url`. 0: begun or already under way.
int fly_bridge_open(const char *url) {
  if (!url || strlen(url) >= FLY_URL) return -1;
  double now = emscripten_get_now();
  pthread_mutex_lock(&lock);
  // an attempt nobody answers - not even with a refusal - is not waited for without end
  int hung = state == 1 && now - attempt_began > FLY_OPENING_MS;
  if (state != 0 && !hung) {
    pthread_mutex_unlock(&lock);
    return 0;
  }
  EMSCRIPTEN_WEBSOCKET_T hanging = 0;
  if (hung) {
    hanging = ws;
    ws = 0;
  }
  state = 1;
  attempt += 1;
  attempt_began = now;
  uintptr_t mine = attempt;
  EMSCRIPTEN_WEBSOCKET_T old = stale;
  stale = 0;
  pthread_mutex_unlock(&lock);
  // never with the lock held: these run on the events' thread, which takes it
  if (old) emscripten_websocket_delete(old);
  if (hanging) {
    emscripten_websocket_close(hanging, 0, 0);
    emscripten_websocket_delete(hanging);
  }
  EmscriptenWebSocketCreateAttributes attributes;
  emscripten_websocket_init_create_attributes(&attributes);
  attributes.url = url;
  EMSCRIPTEN_WEBSOCKET_T made = emscripten_websocket_new(&attributes);
  if (made > 0) {
    void *user = (void *)mine;
    emscripten_websocket_set_onopen_callback_on_thread(made, user, on_open, EM_CALLBACK_THREAD_CONTEXT_MAIN_RUNTIME_THREAD);
    emscripten_websocket_set_onclose_callback_on_thread(made, user, on_close, EM_CALLBACK_THREAD_CONTEXT_MAIN_RUNTIME_THREAD);
    emscripten_websocket_set_onerror_callback_on_thread(made, user, on_error, EM_CALLBACK_THREAD_CONTEXT_MAIN_RUNTIME_THREAD);
    emscripten_websocket_set_onmessage_callback_on_thread(made, user, on_message, EM_CALLBACK_THREAD_CONTEXT_MAIN_RUNTIME_THREAD);
  }
  pthread_mutex_lock(&lock);
  int result = 0;
  if (made <= 0) {
    if (attempt == mine) state = 0;
    result = -1;
  } else if (attempt == mine && state != 0) {
    ws = made;
  } else {
    // it was lost before it was known here
    stale = made;
  }
  pthread_mutex_unlock(&lock);
  return result;
}

// 0: no gateway, 1: connecting, 2: connected.
int fly_bridge_state(void) {
  pthread_mutex_lock(&lock);
  int now = state;
  pthread_mutex_unlock(&lock);
  return now;
}

// One call to the gateway. `a` then `b` are its payload. On success the
// answer's number is returned (never negative) and, if `out` is given, its
// bytes are the caller's to free. On failure -1 and errno.
static int32_t call(uint8_t op, const uint8_t *a, uint32_t alen, const uint8_t *b, uint32_t blen, uint32_t wait_ms, uint8_t **out, uint32_t *outlen) {
  if (out) { *out = NULL; *outlen = 0; }
  if (emscripten_is_main_runtime_thread()) { errno = EDEADLK; return -1; }
  uint32_t size = 5 + alen + blen;
  uint8_t *message = (uint8_t *)malloc(size);
  Call *c = (Call *)calloc(1, sizeof(Call));
  if (!message || !c) { free(message); free(c); errno = ENOMEM; return -1; }
  pthread_mutex_lock(&lock);
  if (state != 2) {
    pthread_mutex_unlock(&lock);
    free(message); free(c);
    errno = ENOTCONN;
    return -1;
  }
  c->id = next_id++;
  if (next_id == 0) next_id = 1;
  c->next = pending;
  pending = c;
  EMSCRIPTEN_WEBSOCKET_T through = ws;
  pthread_mutex_unlock(&lock);
  wr32(message, c->id);
  message[4] = op;
  if (alen) memcpy(message + 5, a, alen);
  if (blen) memcpy(message + 5 + alen, b, blen);
  int sent = emscripten_websocket_send_binary(through, message, size);
  free(message);
  double began = emscripten_get_now();
  for (;;) {
    if (atomic_load(&c->done)) break;
    int over = sent < 0 || (wait_ms > 0 && emscripten_get_now() - began > (double)wait_ms);
    if (over) {
      pthread_mutex_lock(&lock);
      Call *still = atomic_load(&c->done) ? NULL : unlink_call(c->id);
      pthread_mutex_unlock(&lock);
      if (still) {
        free(c);
        errno = sent < 0 ? ENOTCONN : ETIMEDOUT;
        return -1;
      }
      // answered, or failed with the WebSocket, in the meantime
      continue;
    }
    emscripten_futex_wait(&c->done, 0, FLY_SLICE_MS);
  }
  int32_t ret = c->ret, code = c->code;
  uint8_t *data = c->data;
  uint32_t len = c->len;
  free(c);
  if (ret < 0) {
    free(data);
    errno = os_error(code);
    return -1;
  }
  if (out) { *out = data; *outlen = len; } else free(data);
  return ret;
}

// with the lock held
static Slot *slot_of(int fd) {
  if (fd < FLY_BASE || fd >= FLY_BASE + FLY_SLOTS) return NULL;
  Slot *s = &slots[fd - FLY_BASE];
  return s->refs > 0 ? s : NULL;
}

static void close_at_gateway(int32_t handle) {
  uint8_t h[4];
  wr32(h, (uint32_t)handle);
  int kept = errno;
  (void)call(OP_CLOSE, h, 4, NULL, 0, FLY_CALL_MS, NULL, NULL);
  errno = kept;
}

// A connection to the IPv4 address `ip` (four bytes as written) at `port`.
// Returns its descriptor, or -1 and errno.
int fly_dial(const uint8_t *ip, uint16_t port, uint32_t wait_ms) {
  uint8_t to[6] = { (uint8_t)(port >> 8), (uint8_t)port, ip[0], ip[1], ip[2], ip[3] };
  int32_t handle = call(OP_OPEN, to, 6, NULL, 0, wait_ms ? wait_ms + 5000u : FLY_CALL_MS, NULL, NULL);
  if (handle < 0) return -1;
  pthread_mutex_lock(&lock);
  int fd = -1;
  // a WebSocket lost since the answer took the connection with it
  if (state == 2) {
    for (int i = 0; i < FLY_SLOTS; i++) {
      if (slots[i].refs == 0) {
        memset(&slots[i], 0, sizeof(Slot));
        slots[i].refs = 1;
        slots[i].handle = handle;
        slots[i].alive = 1;
        slots[i].peer.sin_family = AF_INET;
        slots[i].peer.sin_port = htons(port);
        memcpy(&slots[i].peer.sin_addr, ip, 4);
        fd = FLY_BASE + i;
        break;
      }
    }
  }
  int gone = state != 2;
  pthread_mutex_unlock(&lock);
  if (fd < 0) {
    if (!gone) close_at_gateway(handle);
    errno = gone ? ECONNRESET : EMFILE;
  }
  return fd;
}

// The same connection held once more; closed when every holder has closed it.
int fly_dup(int fd) {
  pthread_mutex_lock(&lock);
  Slot *s = slot_of(fd);
  if (s) s->refs += 1;
  pthread_mutex_unlock(&lock);
  if (!s) { errno = EBADF; return -1; }
  return fd;
}

// The public IPv4 addresses of `name`, four bytes each, at most `room` of them.
// Returns how many, or -1 and errno.
int fly_resolve(const char *name, uint8_t *out, int room) {
  size_t n = name ? strlen(name) : 0;
  if (n == 0 || n > FLY_MAX_NAME || room <= 0) { errno = EINVAL; return -1; }
  uint8_t *data = NULL;
  uint32_t len = 0;
  int32_t count = call(OP_RESOLVE, (const uint8_t *)name, (uint32_t)n, NULL, 0, FLY_CALL_MS, &data, &len);
  if (count < 0) return -1;
  int given = 0;
  while (given < room && given < count && (uint32_t)(given + 1) * 4u <= len) {
    memcpy(out + given * 4, data + given * 4, 4);
    given += 1;
  }
  free(data);
  return given;
}

ssize_t __real_recv(int fd, void *buffer, size_t length, int flags);
ssize_t __real_send(int fd, const void *buffer, size_t length, int flags);
int __real_shutdown(int fd, int how);
int __real_close(int fd);
int __real_setsockopt(int fd, int level, int name, const void *value, socklen_t length);
int __real_getsockopt(int fd, int level, int name, void *value, socklen_t *length);
int __real_getpeername(int fd, struct sockaddr *address, socklen_t *length);
int __real_getsockname(int fd, struct sockaddr *address, socklen_t *length);

ssize_t __wrap_recv(int fd, void *buffer, size_t length, int flags) {
  pthread_mutex_lock(&lock);
  Slot *s = slot_of(fd);
  int alive = s ? s->alive : 0, lost = s ? s->lost : 0;
  int32_t handle = s ? s->handle : 0;
  uint32_t wait = s ? s->recv_ms : 0;
  pthread_mutex_unlock(&lock);
  if (!s) return __real_recv(fd, buffer, length, flags);
  if (flags & ~MSG_NOSIGNAL) { errno = EOPNOTSUPP; return -1; }
  if (!alive) {
    if (lost) { errno = ECONNRESET; return -1; }
    return 0;
  }
  if (length == 0) return 0;
  uint32_t want = length > FLY_MAX_RECV ? FLY_MAX_RECV : (uint32_t)length;
  uint8_t ask[12];
  wr32(ask, (uint32_t)handle);
  wr32(ask + 4, want);
  wr32(ask + 8, wait);
  uint8_t *data = NULL;
  uint32_t len = 0;
  // the gateway answers "nothing yet" itself when the wait is over
  int32_t got = call(OP_RECV, ask, 12, NULL, 0, wait ? wait + 15000u : 0, &data, &len);
  if (got < 0) return -1;
  if ((uint32_t)got > len || (uint32_t)got > want) {
    free(data);
    errno = EIO;
    return -1;
  }
  if (got > 0) memcpy(buffer, data, (size_t)got);
  free(data);
  return got;
}

ssize_t __wrap_send(int fd, const void *buffer, size_t length, int flags) {
  pthread_mutex_lock(&lock);
  Slot *s = slot_of(fd);
  int alive = s ? s->alive : 0;
  int32_t handle = s ? s->handle : 0;
  pthread_mutex_unlock(&lock);
  if (!s) return __real_send(fd, buffer, length, flags);
  if (!alive) { errno = EPIPE; return -1; }
  if (length == 0) return 0;
  uint32_t part = length > FLY_MAX_SEND ? FLY_MAX_SEND : (uint32_t)length;
  uint8_t h[4];
  wr32(h, (uint32_t)handle);
  int32_t sent = call(OP_SEND, h, 4, (const uint8_t *)buffer, part, FLY_CALL_MS, NULL, NULL);
  if (sent < 0) return -1;
  return (uint32_t)sent > part ? (ssize_t)part : (ssize_t)sent;
}

// with the lock held: the connection is closed here; returns whether the
// gateway is still to be told
static int end_locked(Slot *s) {
  int tell = s->alive;
  s->alive = 0;
  return tell;
}

// Reading into and writing from several pieces at once (the secure channel
// writes so): one piece a call - the caller is told how much was done and
// comes again for the rest, as with any short read or write.
ssize_t __real_readv(int fd, const struct iovec *pieces, int count);
ssize_t __real_writev(int fd, const struct iovec *pieces, int count);

static int is_ours(int fd) {
  pthread_mutex_lock(&lock);
  int ours = slot_of(fd) != NULL;
  pthread_mutex_unlock(&lock);
  return ours;
}

ssize_t __wrap_readv(int fd, const struct iovec *pieces, int count) {
  if (!is_ours(fd)) return __real_readv(fd, pieces, count);
  for (int i = 0; i < count; i++) {
    if (pieces[i].iov_len > 0) return __wrap_recv(fd, pieces[i].iov_base, pieces[i].iov_len, 0);
  }
  return 0;
}

ssize_t __wrap_writev(int fd, const struct iovec *pieces, int count) {
  if (!is_ours(fd)) return __real_writev(fd, pieces, count);
  for (int i = 0; i < count; i++) {
    if (pieces[i].iov_len > 0) return __wrap_send(fd, pieces[i].iov_base, pieces[i].iov_len, 0);
  }
  return 0;
}

int __wrap_shutdown(int fd, int how) {
  pthread_mutex_lock(&lock);
  Slot *s = slot_of(fd);
  int tell = s ? end_locked(s) : 0;
  int32_t handle = s ? s->handle : 0;
  pthread_mutex_unlock(&lock);
  if (!s) return __real_shutdown(fd, how);
  // one direction cannot be closed alone at the gateway: both are
  if (tell) close_at_gateway(handle);
  return 0;
}

int __wrap_close(int fd) {
  pthread_mutex_lock(&lock);
  Slot *s = slot_of(fd);
  int tell = 0;
  int32_t handle = 0;
  if (s) {
    s->refs -= 1;
    if (s->refs == 0) {
      tell = end_locked(s);
      handle = s->handle;
    }
  }
  pthread_mutex_unlock(&lock);
  if (!s) return __real_close(fd);
  if (tell) close_at_gateway(handle);
  return 0;
}

static uint32_t millis(const void *value, socklen_t length) {
  if (!value || length < sizeof(struct timeval)) return 0;
  struct timeval t;
  memcpy(&t, value, sizeof t);
  if (t.tv_sec < 0 || t.tv_usec < 0) return 0;
  uint64_t ms = (uint64_t)t.tv_sec * 1000u + (uint64_t)t.tv_usec / 1000u;
  if (ms == 0 && t.tv_usec > 0) ms = 1;
  return ms > 3600000u ? 3600000u : (uint32_t)ms;
}

int __wrap_setsockopt(int fd, int level, int name, const void *value, socklen_t length) {
  pthread_mutex_lock(&lock);
  Slot *s = slot_of(fd);
  if (s && level == SOL_SOCKET && name == SO_RCVTIMEO) s->recv_ms = millis(value, length);
  pthread_mutex_unlock(&lock);
  if (!s) return __real_setsockopt(fd, level, name, value, length);
  // the rest (no delay, the time a write may take) changes nothing here
  return 0;
}

int __wrap_getsockopt(int fd, int level, int name, void *value, socklen_t *length) {
  pthread_mutex_lock(&lock);
  Slot *s = slot_of(fd);
  uint32_t wait = s ? s->recv_ms : 0;
  pthread_mutex_unlock(&lock);
  if (!s) return __real_getsockopt(fd, level, name, value, length);
  if (!value || !length) { errno = EFAULT; return -1; }
  if (level == SOL_SOCKET && name == SO_RCVTIMEO && *length >= sizeof(struct timeval)) {
    struct timeval t = { .tv_sec = wait / 1000u, .tv_usec = (wait % 1000u) * 1000u };
    memcpy(value, &t, sizeof t);
    *length = sizeof t;
    return 0;
  }
  if (*length >= sizeof(int)) {
    int zero = 0;
    memcpy(value, &zero, sizeof zero);
    *length = sizeof zero;
    return 0;
  }
  errno = EINVAL;
  return -1;
}

static int give_address(const struct sockaddr_in *from, struct sockaddr *address, socklen_t *length) {
  if (!address || !length) { errno = EFAULT; return -1; }
  socklen_t n = *length < sizeof *from ? *length : (socklen_t)sizeof *from;
  memcpy(address, from, n);
  *length = sizeof *from;
  return 0;
}

int __wrap_getpeername(int fd, struct sockaddr *address, socklen_t *length) {
  pthread_mutex_lock(&lock);
  Slot *s = slot_of(fd);
  struct sockaddr_in peer;
  memset(&peer, 0, sizeof peer);
  if (s) peer = s->peer;
  pthread_mutex_unlock(&lock);
  if (!s) return __real_getpeername(fd, address, length);
  return give_address(&peer, address, length);
}

int __wrap_getsockname(int fd, struct sockaddr *address, socklen_t *length) {
  pthread_mutex_lock(&lock);
  Slot *s = slot_of(fd);
  pthread_mutex_unlock(&lock);
  if (!s) return __real_getsockname(fd, address, length);
  // the module has no address of its own on any network
  struct sockaddr_in none;
  memset(&none, 0, sizeof none);
  none.sin_family = AF_INET;
  return give_address(&none, address, length);
}
