#pragma once

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <system_error>

#include <fcntl.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

#include <linux/io_uring.h>

namespace brighttpd
{

class io_uring_ring
{
public:
    explicit io_uring_ring(unsigned entries)
    {
        init_ring(entries);

        if (params_.flags & IORING_SETUP_NO_SQARRAY)
        {
            sq_ring_size_ = params_.cq_off.cqes + params_.cq_entries * sizeof(io_uring_cqe);
        }
        else
        {
            sq_ring_size_ = params_.sq_off.array + params_.sq_entries * sizeof(__u32);
        }

        cq_ring_size_ = params_.cq_off.cqes + params_.cq_entries * sizeof(io_uring_cqe);

        if (params_.features & IORING_FEAT_SINGLE_MMAP)
        {
            if (cq_ring_size_ > sq_ring_size_)
            {
                sq_ring_size_ = cq_ring_size_;
            }
            else
            {
                cq_ring_size_ = sq_ring_size_;
            }
        }

        sq_ring_ptr_ = static_cast<char*>(::mmap(
                                              nullptr, sq_ring_size_, PROT_READ | PROT_WRITE,
                                              MAP_SHARED | MAP_POPULATE, ring_fd_, IORING_OFF_SQ_RING));

        if (sq_ring_ptr_ == MAP_FAILED)
        {
            throw std::system_error(errno, std::generic_category(), "mmap sq ring");
        }

        if (params_.features & IORING_FEAT_SINGLE_MMAP)
        {
            cq_ring_ptr_ = sq_ring_ptr_;
        }
        else
        {
            cq_ring_ptr_ = static_cast<char*>(::mmap(
                                                  nullptr, cq_ring_size_, PROT_READ | PROT_WRITE,
                                                  MAP_SHARED | MAP_POPULATE, ring_fd_, IORING_OFF_CQ_RING));

            if (cq_ring_ptr_ == MAP_FAILED)
            {
                throw std::system_error(errno, std::generic_category(), "mmap cq ring");
            }
        }

        sqes_ = static_cast<io_uring_sqe*>(::mmap(
                                               nullptr, params_.sq_entries * sizeof(io_uring_sqe), PROT_READ | PROT_WRITE,
                                               MAP_SHARED | MAP_POPULATE, ring_fd_, IORING_OFF_SQES));

        if (sqes_ == MAP_FAILED)
        {
            throw std::system_error(errno, std::generic_category(), "mmap sqes");
        }

        sq_head_ = reinterpret_cast<unsigned*>(sq_ring_ptr_ + params_.sq_off.head);
        sq_tail_ = reinterpret_cast<unsigned*>(sq_ring_ptr_ + params_.sq_off.tail);
        sq_mask_ = reinterpret_cast<unsigned*>(sq_ring_ptr_ + params_.sq_off.ring_mask);
        sq_entries_ = reinterpret_cast<unsigned*>(sq_ring_ptr_ + params_.sq_off.ring_entries);
        sq_flags_ = reinterpret_cast<unsigned*>(sq_ring_ptr_ + params_.sq_off.flags);

        if (params_.flags & IORING_SETUP_NO_SQARRAY)
        {
            sq_array_ = nullptr;
        }
        else
        {
            sq_array_ = reinterpret_cast<unsigned*>(sq_ring_ptr_ + params_.sq_off.array);
        }

        cq_head_ = reinterpret_cast<unsigned*>(cq_ring_ptr_ + params_.cq_off.head);
        cq_tail_ = reinterpret_cast<unsigned*>(cq_ring_ptr_ + params_.cq_off.tail);
        cq_mask_ = reinterpret_cast<unsigned*>(cq_ring_ptr_ + params_.cq_off.ring_mask);
        cq_entries_ = reinterpret_cast<unsigned*>(cq_ring_ptr_ + params_.cq_off.ring_entries);
        cqes_ring_ = reinterpret_cast<io_uring_cqe*>(cq_ring_ptr_ + params_.cq_off.cqes);
    }

    io_uring_ring(const io_uring_ring&) = delete;
    io_uring_ring& operator=(const io_uring_ring&) = delete;

    ~io_uring_ring()
    {
        if (sqes_ && sqes_ != MAP_FAILED)
        {
            ::munmap(sqes_, params_.sq_entries * sizeof(io_uring_sqe));
        }

        if (cq_ring_ptr_ && cq_ring_ptr_ != MAP_FAILED && cq_ring_ptr_ != sq_ring_ptr_)
        {
            ::munmap(cq_ring_ptr_, cq_ring_size_);
        }

        if (sq_ring_ptr_ && sq_ring_ptr_ != MAP_FAILED)
        {
            ::munmap(sq_ring_ptr_, sq_ring_size_);
        }

        if (ring_fd_ >= 0)
        {
            ::close(ring_fd_);
        }
    }

    io_uring_sqe* get_sqe()
    {
        const unsigned head = *sq_head_;
        unsigned tail = *sq_tail_;

        if (tail - head >= *sq_entries_)
        {
            return nullptr;
        }

        io_uring_sqe *sqe = &sqes_[tail & *sq_mask_];
        std::memset(sqe, 0, sizeof(*sqe));

        if (sq_array_)
        {
            sq_array_[tail & *sq_mask_] = tail & *sq_mask_;
        }

        *sq_tail_ = tail + 1;
        return sqe;
    }

    int submit()
    {
        return enter(pending_sqes(), 0, 0);
    }

    int submit_and_wait(unsigned wait_for)
    {
        return enter(pending_sqes(), wait_for, IORING_ENTER_GETEVENTS);
    }

    int get_events(unsigned wait_for)
    {
        return enter(0, wait_for, IORING_ENTER_GETEVENTS);
    }

    int register_files(const int* files, unsigned count)
    {
        return static_cast<int>(::syscall(
                                    SYS_io_uring_register, ring_fd_, IORING_REGISTER_FILES, files, count));
    }

    int register_buffers(const struct iovec *iovecs, unsigned count)
    {
        return static_cast<int>(::syscall(
                                    SYS_io_uring_register, ring_fd_, IORING_REGISTER_BUFFERS, iovecs, count));
    }

    int unregister_buffers()
    {
        return static_cast<int>(::syscall(
                                    SYS_io_uring_register, ring_fd_, IORING_UNREGISTER_BUFFERS, nullptr, 0));
    }

    bool using_sqpoll() const
    {
        return (params_.flags & IORING_SETUP_SQPOLL) != 0;
    }

    bool has_sqpoll_nonfixed() const
    {
        return (params_.features & IORING_FEAT_SQPOLL_NONFIXED) != 0;
    }

    bool has_fast_poll() const
    {
        return (params_.features & IORING_FEAT_FAST_POLL) != 0;
    }

    unsigned pending() const
    {
        return pending_sqes();
    }

    io_uring_cqe* peek_cqe()
    {
        const unsigned head = *cq_head_;

        if (head == *cq_tail_)
        {
            return nullptr;
        }

        return &cqes_ring_[head & *cq_mask_];
    }

    void cqe_seen()
    {
        ++(*cq_head_);
    }

    static void prep_accept(io_uring_sqe *sqe, int fd, sockaddr *addr, socklen_t* addrlen, unsigned flags = 0)
    {
        sqe->opcode = IORING_OP_ACCEPT;
        sqe->fd = fd;
        sqe->addr = reinterpret_cast<__u64>(addr);
        sqe->off = reinterpret_cast<__u64>(addrlen);
        sqe->accept_flags = flags;
    }

    static void prep_accept_multishot(io_uring_sqe *sqe, int fd, unsigned flags = 0)
    {
        prep_accept(sqe, fd, nullptr, nullptr, flags);
        sqe->ioprio = IORING_ACCEPT_MULTISHOT;
    }

    // POLL_FIRST: arm a kernel poll before issuing the recv so we don't
    // submit a syscall that will just return -EAGAIN
    static void prep_recv(io_uring_sqe *sqe, int fd, void* buf, unsigned len, unsigned flags = 0)
    {
        sqe->opcode = IORING_OP_RECV;
        sqe->fd = fd;
        sqe->addr = reinterpret_cast<__u64>(buf);
        sqe->len = len;
        sqe->msg_flags = flags;
        sqe->ioprio |= IORING_RECVSEND_POLL_FIRST;
    }

    static void prep_read(io_uring_sqe *sqe, int fd, void* buf, unsigned len, std::uint64_t offset)
    {
        sqe->opcode = IORING_OP_READ;
        sqe->fd = fd;
        sqe->addr = reinterpret_cast<__u64>(buf);
        sqe->len = len;
        sqe->off = offset;
    }

    static void prep_read_fixed(io_uring_sqe *sqe, int fixed_fd, void* buf, unsigned len, std::uint64_t offset)
    {
        prep_read(sqe, fixed_fd, buf, len, offset);
        sqe->flags |= IOSQE_FIXED_FILE;
    }

    static void prep_read_buf_fixed(io_uring_sqe *sqe, int fd, unsigned buf_index, unsigned len, std::uint64_t offset)
    {
        sqe->opcode = IORING_OP_READ_FIXED;
        sqe->fd = fd;
        sqe->addr = 0;
        sqe->len = len;
        sqe->off = offset;
        sqe->buf_index = buf_index;
    }

    static void prep_send(io_uring_sqe *sqe, int fd, const void* buf, unsigned len, unsigned flags = 0)
    {
        sqe->opcode = IORING_OP_SEND;
        sqe->fd = fd;
        sqe->addr = reinterpret_cast<__u64>(buf);
        sqe->len = len;
        sqe->msg_flags = flags;
        sqe->ioprio |= IORING_RECVSEND_POLL_FIRST;
    }

    static void prep_sendmsg(io_uring_sqe *sqe, int fd, const msghdr *msg, unsigned flags = 0)
    {
        sqe->opcode = IORING_OP_SENDMSG;
        sqe->fd = fd;
        sqe->addr = reinterpret_cast<__u64>(msg);
        sqe->len = 1;
        sqe->msg_flags = flags;
        sqe->ioprio |= IORING_RECVSEND_POLL_FIRST;
    }

    static void prep_send_zc(io_uring_sqe *sqe, int fd, const void* buf, unsigned len, unsigned flags = 0,
                             unsigned buf_index = 0)
    {
        sqe->opcode = IORING_OP_SEND_ZC;
        sqe->fd = fd;
        sqe->addr = reinterpret_cast<__u64>(buf);
        sqe->len = len;
        sqe->msg_flags = flags;
        sqe->buf_index = buf_index;
    }

    static void prep_sendmsg_zc(io_uring_sqe *sqe, int fd, const msghdr *msg, unsigned flags = 0)
    {
        sqe->opcode = IORING_OP_SENDMSG_ZC;
        sqe->fd = fd;
        sqe->addr = reinterpret_cast<__u64>(msg);
        sqe->len = 1;
        sqe->msg_flags = flags;
    }

    static void prep_splice(
        io_uring_sqe *sqe,
        int fd_in,
        std::int64_t off_in,
        int fd_out,
        std::int64_t off_out,
        unsigned len,
        unsigned splice_flags = 0)
    {
        sqe->opcode = IORING_OP_SPLICE;
        sqe->fd = fd_out;
        sqe->splice_fd_in = fd_in;
        sqe->off = static_cast<__u64>(off_out);
        sqe->addr = static_cast<__u64>(off_in);
        sqe->len = len;
        sqe->splice_flags = splice_flags;
    }

    static void prep_close(io_uring_sqe *sqe, int fd)
    {
        sqe->opcode = IORING_OP_CLOSE;
        sqe->fd = fd;
    }

    static void prep_poll_add(io_uring_sqe *sqe, int fd, unsigned poll_mask)
    {
        sqe->opcode = IORING_OP_POLL_ADD;
        sqe->fd = fd;
        sqe->poll_events = static_cast<__poll_t>(poll_mask);
    }

    static void prep_timeout(io_uring_sqe *sqe, const __kernel_timespec *ts, unsigned count = 0, unsigned flags = 0)
    {
        sqe->opcode = IORING_OP_TIMEOUT;
        sqe->addr = reinterpret_cast<__u64>(ts);
        sqe->len = count;
        sqe->timeout_flags = flags;
    }

    static void prep_recv_multishot(io_uring_sqe *sqe, int fd, unsigned flags = 0)
    {
        sqe->opcode = IORING_OP_RECV;
        sqe->fd = fd;
        sqe->addr = 0;
        sqe->len = 0;
        sqe->msg_flags = flags;
        sqe->ioprio |= IORING_RECVSEND_POLL_FIRST | IORING_RECV_MULTISHOT;
    }

    static void buf_ring_add(io_uring_buf_ring *ring, void* buf, unsigned len, __u16 bid, unsigned mask, unsigned offset)
    {
        const unsigned idx = (ring->tail + offset) & mask;
        ring->bufs[idx].addr = reinterpret_cast<__u64>(buf);
        ring->bufs[idx].len = len;
        ring->bufs[idx].bid = bid;
    }

    static void buf_ring_advance(io_uring_buf_ring *ring, unsigned count)
    {
        __atomic_store_n(&ring->tail, ring->tail + count, __ATOMIC_RELEASE);
    }

    static unsigned buf_ring_mask(unsigned count)
    {
        return count - 1;
    }

    int register_buf_ring(const struct io_uring_buf_reg *reg)
    {
        return static_cast<int>(::syscall(
                                    SYS_io_uring_register, ring_fd_, IORING_REGISTER_PBUF_RING, reg, 1));
    }

    int unregister_buf_ring(__u16 bgid)
    {
        struct io_uring_buf_reg reg {};

        reg.ring_entries = 0;
        reg.bgid = bgid;
        return static_cast<int>(::syscall(
                                    SYS_io_uring_register, ring_fd_, IORING_UNREGISTER_PBUF_RING, &reg, 1));
    }

    io_uring_buf_ring* setup_buf_ring(__u16 bgid, unsigned num_bufs)
    {
        struct io_uring_buf_reg reg {};

        reg.ring_entries = num_bufs;
        reg.bgid = bgid;
        reg.flags = IOU_PBUF_RING_MMAP;
        int ret = register_buf_ring(&reg);

        if (ret < 0)
        {
            throw std::system_error(-ret, std::generic_category(), "register_buf_ring");
        }

        void* ptr = ::mmap(
                        nullptr,
                        num_bufs * sizeof(struct io_uring_buf),
                        PROT_READ | PROT_WRITE,
                        MAP_SHARED | MAP_POPULATE,
                        ring_fd_,
                        IORING_OFF_PBUF_RING | (bgid << IORING_OFF_PBUF_SHIFT));

        if (ptr == MAP_FAILED)
        {
            throw std::system_error(errno, std::generic_category(), "mmap buf_ring");
        }

        return static_cast<io_uring_buf_ring*>(ptr);
    }

    void free_buf_ring(io_uring_buf_ring *ring, __u16 bgid, unsigned num_bufs)
    {
        ::munmap(ring, num_bufs * sizeof(struct io_uring_buf));
        unregister_buf_ring(bgid);
    }

private:
    void init_ring(unsigned entries)
    {
        const unsigned preferred_flags =
            IORING_SETUP_SINGLE_ISSUER |
            IORING_SETUP_COOP_TASKRUN |
            IORING_SETUP_DEFER_TASKRUN |
            IORING_SETUP_TASKRUN_FLAG |
            IORING_SETUP_NO_SQARRAY |
            IORING_SETUP_SUBMIT_ALL |
            IORING_SETUP_SQPOLL;

        if (!try_setup(entries, preferred_flags))
        {
            const unsigned fallback_flags =
                IORING_SETUP_SINGLE_ISSUER |
                IORING_SETUP_COOP_TASKRUN |
                IORING_SETUP_DEFER_TASKRUN |
                IORING_SETUP_TASKRUN_FLAG |
                IORING_SETUP_NO_SQARRAY |
                IORING_SETUP_SUBMIT_ALL;

            if (!try_setup(entries, fallback_flags))
            {
                std::memset(&params_, 0, sizeof(params_));
                ring_fd_ = static_cast<int>(::syscall(SYS_io_uring_setup, entries, &params_));

                if (ring_fd_ < 0)
                {
                    throw std::system_error(errno, std::generic_category(), "io_uring_setup");
                }
            }
        }

        if ((params_.features & IORING_FEAT_FAST_POLL) == 0)
        {
            ::close(ring_fd_);
            ring_fd_ = -1;
            throw std::runtime_error("io_uring setup missing required IORING_FEAT_FAST_POLL");
        }
    }

    bool try_setup(unsigned entries, unsigned flags)
    {
        std::memset(&params_, 0, sizeof(params_));
        params_.flags = flags;
        ring_fd_ = static_cast<int>(::syscall(SYS_io_uring_setup, entries, &params_));
        return ring_fd_ >= 0;
    }

    int enter(unsigned to_submit, unsigned wait_for, unsigned flags)
    {
        return static_cast<int>(::syscall(SYS_io_uring_enter, ring_fd_,
                                          to_submit, wait_for, flags, nullptr, 0));
    }

    unsigned pending_sqes() const
    {
        return *sq_tail_ - *sq_head_;
    }

    io_uring_params params_{};
    int ring_fd_{-1};

    char* sq_ring_ptr_{nullptr};
    char* cq_ring_ptr_{nullptr};
    io_uring_sqe* sqes_{nullptr};

    std::size_t sq_ring_size_{0};
    std::size_t cq_ring_size_{0};

    unsigned* sq_head_{nullptr};
    unsigned* sq_tail_{nullptr};
    unsigned* sq_mask_{nullptr};
    unsigned* sq_entries_{nullptr};
    unsigned* sq_flags_{nullptr};
    unsigned* sq_array_{nullptr};

    unsigned* cq_head_{nullptr};
    unsigned* cq_tail_{nullptr};
    unsigned* cq_mask_{nullptr};
    unsigned* cq_entries_{nullptr};
    io_uring_cqe* cqes_ring_{nullptr};
};

}  // namespace brighttpd
