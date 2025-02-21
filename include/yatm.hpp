/*
** MIT License
**
** Copyright(c) 2019, Pantelis Lekakis
**
** Permission is hereby granted, free of charge, to any person obtaining a copy
** of this software and associated documentation files(the "Software"), to deal
** in the Software without restriction, including without limitation the rights
** to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
** copies of the Software, and to permit persons to whom the Software is
** furnished to do so, subject to the following conditions :
**
** The above copyright notice and this permission notice shall be included in all
** copies or substantial portions of the Software.
**
** THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
** IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
** FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
** AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
** LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
** OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
** SOFTWARE.
*/

#pragma once

#include <vector>
#include <algorithm>
#include <cstdlib>
#include <cassert>
#include <functional>
#include <algorithm>
#include <limits.h>
#include <memory.h>
#include <random>
#include <queue>

// Compiler detection
#ifdef _MSC_VER
	#define YATM_COMPILER_MSVC 1
#elif defined(__GNUC__) || defined(__GNUG__)
	#define YATM_COMPILER_GCC 1
#elif defined(__clang)
	#define YATM_COMPILER_CLANG 1
#else
	#error Unsupported compiler
#endif // _MSC_VER

// Platform detection
#ifdef _WIN32
	#define YATM_PLATFORM_WINDOWS 1
#elif defined(__APPLE__)
	#define YATM_PLATFORM_APPLE 1
#elif defined(__unix__)
	#define YATM_PLATFORM_UNIX 1
#elif defined(__linux__)
	#define YATM_PLATFORM_LINUX 1
#else
	#error Unsupported platform
#endif

// Make sure we don't have the following already defined.
#if defined(YATM_WIN64) || defined(YATM_NIX) || defined(YATM_APPLE)
	#error yatm implementation already defined, this is not allowed
#endif

// Initial codepath support based on platform
#if YATM_PLATFORM_WINDOWS
	#define YATM_WIN64 1	
#elif YATM_PLATFORM_APPLE
	#define YATM_APPLE 1
#elif YATM_PLATFORM_UNIX || YATM_PLATFORM_LINUX
	#define YATM_NIX 1
#endif // YATM_PLATFORM_WINDOWS

#ifndef YATM_MALLOC_INIT
	#define YATM_MALLOC_INIT
#endif // YATM_MALLOC_INIT

#ifndef YATM_MALLOC_DEINIT
	#define YATM_MALLOC_DEINIT
#endif // YATM_MALLOC_DEINIT

#ifndef YATM_ENABLE_WORK_STEALING
	#define YATM_ENABLE_WORK_STEALING (1u)
#endif // YATM_ENABLE_WORK_STEALING

#ifndef YATM_CACHE_LINE_SIZE
	#define YATM_CACHE_LINE_SIZE (64u)
#endif // YATM_CACHE_SIZE

#ifndef YATM_DEFAULT_STACK_SIZE
	#define YATM_DEFAULT_STACK_SIZE (1024u * 1024u)
#endif // YATM_DEFAULT_STACK_SIZE

#ifndef YATM_ASSERT
	#define YATM_ASSERT(x) assert((x))
#endif // YATM_ASSERT

#ifndef YATM_TTY
	#define YATM_TTY(x) std::cout << (x) << std::endl
#endif // YATM_TTY

#ifndef YATM_WORKER_SCOPE
	#define YATM_WORKER_SCOPE(label)
#endif // YATM_WORKER_SCOPE

#ifndef YATM_DEBUG
	#ifdef _MSC_VER
		#define YATM_DEBUG (_DEBUG)
	#endif //_MSC_VER
#endif // YATM_DEBUG

#if YATM_WIN64
	#define NOMINMAX
	#define WIN32_LEAN_AND_MEAN
	#include <Windows.h>
	#define YATM_WIN64_ATOMICS 1
	#define YATM_USE_RW_LOCKS 1
#elif YATM_NIX || YATM_APPLE
	#include <unistd.h>
	#define YATM_GCC_ATOMICS 1
#endif // YATM_WIN64

#define YATM_USE_PTHREADS (YATM_NIX || YATM_APPLE)

#if YATM_USE_PTHREADS
	#include <pthread.h>
#endif // YATM_USE_PTHREADS

#if !(YATM_GCC_ATOMICS || YATM_WIN64_ATOMICS)
	#error Unknown atomics implementation
#endif

// Some defaults for reserving space in the job queues

#ifndef YATM_DEFAULT_JOB_QUEUE_RESERVATION
	#define YATM_DEFAULT_JOB_QUEUE_RESERVATION (1024u)
#endif // YATM_DEFAULT_JOB_QUEUE_RESERVATION

#ifndef YATM_DEFAULT_PENDING_JOB_QUEUE_RESERVATION
	#define YATM_DEFAULT_PENDING_JOB_QUEUE_RESERVATION (128u)
#endif // YATM_DEFAULT_PENDING_JOB_QUEUE_RESERVATION

#define YATM_ATOMIC_ALIGN alignas(8) volatile

#if YATM_COMPILER_MSVC
	#define YATM_ALLOCA(x) _malloca((x))
	#define YATM_FREEA(x) _freea((x))
#else
	#define YATM_ALLOCA(x) alloca((x))
	#define YATM_FREEA(x) 
#endif

namespace yatm
{
	// -----------------------------------------------------------------------------------------------
	// A portable aligned allocation mechanism.
	//
	// Thanks to: https://gist.github.com/dblalock/255e76195676daa5cbc57b9b36d1c99a
	// -----------------------------------------------------------------------------------------------

	// -----------------------------------------------------------------------------------------------
	class default_alloc
	{
	public:
		static void* aligned_alloc(uint64_t _size, uint64_t _alignment)
		{
			YATM_ASSERT(_alignment < UINT8_MAX);

			// over-allocate using malloc and adjust pointer by the offset needed to align the memory to specified alignment
			const auto request_size = _size + _alignment;
			uint8_t* buf = (uint8_t*)malloc(request_size);

			// figure out how much we should offset our allocation by
			const uint64_t remainder = ((uint64_t)buf) % _alignment;
			const uint64_t offset = _alignment - remainder;
			uint8_t* ret = buf + (uint8_t)offset;

			// store how many extra bytes we allocated in the byte just before the pointer we return
			*(uint8_t*)(ret - 1) = (uint8_t)offset;

			return ret;
		}

		// -----------------------------------------------------------------------------------------------
		static void aligned_free(const void* const aligned_ptr)
		{
			// find the base allocation by extracting the stored aligned offset and free it
			uint32_t offset = *(((uint8_t*)aligned_ptr) - 1);
			free(((uint8_t*)aligned_ptr) - offset);
		}
	};
}

#ifndef YATM_ALLOC
	#define YATM_ALLOC(type, alignment) yatm::default_alloc::aligned_alloc(sizeof(type), (alignment));
#endif // YATM_ALLOC

#ifndef YATM_ALLOC_COUNT
	#define YATM_ALLOC_COUNT(type, count, alignment) yatm::default_alloc::aligned_alloc(sizeof(type) * (count), (alignment));
#endif // YATM_ALLOC_COUNT

#ifndef YATM_FREE
	#define YATM_FREE(ptr) yatm::default_alloc::aligned_free((ptr))
#endif // YATM_fREE

namespace yatm
{
	static_assert(sizeof(void*) == 8, "Only 64bit platforms are currently supported");

	// -----------------------------------------------------------------------------------------------
	// Thread priority.
	// -----------------------------------------------------------------------------------------------
	enum class thread_priority : uint8_t
	{
		lowest,
		below_normal,
		normal,
		above_normal,
		highest,
		time_critical
	};

	// -----------------------------------------------------------------------------------------------
	// Helper templated random function.
	// -----------------------------------------------------------------------------------------------
	template<typename T>
	T random(T _from, T _to)
	{
		std::random_device                  device;
		std::mt19937                        generator(device());
		std::uniform_int_distribution<T>    distr(_from, _to);
		return distr(generator);
	}

	// -----------------------------------------------------------------------------------------------
	// Prevent copy & move operations.
	// -----------------------------------------------------------------------------------------------
	class no_copy_no_move
	{
	public:
		no_copy_no_move() = default;
		no_copy_no_move(const no_copy_no_move&) = delete;
		no_copy_no_move& operator=(const no_copy_no_move&) = delete;
		no_copy_no_move(no_copy_no_move&&) = delete;
		no_copy_no_move& operator=(no_copy_no_move&&) = delete;
	};

	// -----------------------------------------------------------------------------------------------
	// Prevent copy.
	// -----------------------------------------------------------------------------------------------
	class no_copy
	{
	public:
		no_copy() = default;
		no_copy(const no_copy&) = delete;
		no_copy& operator=(const no_copy&) = delete;
	};

	// -----------------------------------------------------------------------------------------------
	// std::bind wrapper, used specifically for the job callbacks.
	// -----------------------------------------------------------------------------------------------
	template<typename Fx, typename... Args>
	static auto bind(Fx&& _function, Args&&... _args)
	{
		return std::bind(std::forward<Fx>(_function), std::forward<Args>(_args)..., std::placeholders::_1);
	}

	// -----------------------------------------------------------------------------------------------
	// Align input to the next specified alignment.
	// -----------------------------------------------------------------------------------------------
	static uint64_t align(uint64_t _value, uint64_t _align)
	{
		return (_value + (_align - 1)) & ~(_align - 1);
	}

	// -----------------------------------------------------------------------------------------------
	// Align pointer to the next specified alignment.
	// -----------------------------------------------------------------------------------------------
	static uint8_t* align_ptr(uint8_t* _ptr, uint64_t _align)
	{
		return (uint8_t*)align((uint64_t)_ptr, _align);
	}

	// -----------------------------------------------------------------------------------------------
	// Interlocked API for atomic operations.
	// -----------------------------------------------------------------------------------------------
	class atomic : public no_copy_no_move
	{
	public:
		static int32_t interlocked_increment(int32_t volatile* _addend)
		{
#if YATM_WIN64_ATOMICS
			return InterlockedIncrement((LONG volatile*)_addend);
#elif YATM_GCC_ATOMICS
			return __sync_add_and_fetch_4(_addend, 1);
#endif
		}

		static int64_t interlocked_increment64(int64_t volatile* _addend)
		{
#if YATM_WIN64_ATOMICS
			return InterlockedIncrement64((LONG64 volatile*)_addend);
#elif YATM_GCC_ATOMICS
			return __sync_add_and_fetch_8(_addend, 1);
#endif
		}

		static int32_t interlocked_decrement(int32_t volatile* _addend)
		{
#if YATM_WIN64_ATOMICS
			return InterlockedDecrement((LONG volatile*)_addend);
#elif YATM_GCC_ATOMICS
			return __sync_sub_and_fetch_4(_addend, 1);
#endif
		}

		static int64_t interlocked_decrement64(int64_t volatile* _addend)
		{
#if YATM_WIN64_ATOMICS
			return InterlockedDecrement64((LONG64 volatile*)_addend);
#elif YATM_GCC_ATOMICS
			return __sync_sub_and_fetch_8(_addend, 1);
#endif
		}

		static int32_t interlocked_add(int32_t volatile* _addend, int32_t _value)
		{
#if YATM_WIN64_ATOMICS		
			return InterlockedAdd((LONG volatile*)_addend, (LONG)_value);
#elif YATM_GCC_ATOMICS
			return __sync_add_and_fetch_4(_addend, _value);
#endif
		}

		static int64_t interlocked_add64(int64_t volatile* _addend, int64_t _value)
		{
#if YATM_WIN64_ATOMICS		
			return InterlockedAdd64((LONG64 volatile*)_addend, (LONG64)_value);
#elif YATM_GCC_ATOMICS
			return __sync_add_and_fetch_8(_addend, _value);
#endif
		}

		static int32_t interlocked_and(int32_t volatile* _addend, int32_t _value)
		{
#if YATM_WIN64_ATOMICS
			return InterlockedAnd((LONG volatile*)_addend, (LONG)_value);
#elif YATM_GCC_ATOMICS
			return __sync_fetch_and_and_4(_addend, _value);
#endif
		}

		static int64_t interlocked_and64(int64_t volatile* _addend, int64_t _value)
		{
#if YATM_WIN64_ATOMICS
			return InterlockedAnd64((LONG64 volatile*)_addend, (LONG64)_value);
#elif YATM_GCC_ATOMICS
			return __sync_fetch_and_and_8(_addend, _value);
#endif
		}

		static int32_t interlocked_or(int32_t volatile* _addend, int32_t _value)
		{
#if YATM_WIN64_ATOMICS
			return InterlockedOr((LONG volatile*)_addend, (LONG)_value);
#elif YATM_GCC_ATOMICS
			return __sync_fetch_and_or_4(_addend, _value);
#endif
		}

		static int64_t interlocked_or64(int64_t volatile* _addend, int64_t _value)
		{
#if YATM_WIN64_ATOMICS
			return InterlockedOr64((LONG64 volatile*)_addend, (LONG64)_value);
#elif YATM_GCC_ATOMICS
			return __sync_fetch_and_or_8(_addend, _value);
#endif
		}

		static int32_t interlocked_xor(int32_t volatile* _addend, int32_t _value)
		{
#if YATM_WIN64_ATOMICS
			return InterlockedXor((LONG volatile*)_addend, (LONG)_value);
#elif YATM_GCC_ATOMICS
			return __sync_fetch_and_xor_4(_addend, _value);
#endif
		}

		static int64_t interlocked_xor64(int64_t volatile* _addend, int64_t _value)
		{
#if YATM_WIN64_ATOMICS
			return InterlockedXor64((LONG64 volatile*)_addend, (LONG64)_value);
#elif YATM_GCC_ATOMICS
			return __sync_fetch_and_xor_8(_addend, _value);
#endif
		}

		static int32_t interlocked_exchange_add(int32_t volatile* _destination, int32_t _value)
		{
#if YATM_WIN64_ATOMICS
			return InterlockedExchangeAdd((LONG volatile*)_destination, (LONG)_value);
#elif YATM_GCC_ATOMICS
			return __sync_fetch_and_add_4(_destination, _value);
#endif
		}

		static int64_t interlocked_exchange_add64(int64_t volatile* _destination, int64_t _value)
		{
#if YATM_WIN64_ATOMICS
			return InterlockedExchangeAdd64((LONG64 volatile*)_destination, (LONG64)_value);
#elif YATM_GCC_ATOMICS
			return __sync_fetch_and_add_8(_destination, _value);
#endif
		}

		static int32_t interlocked_exchange(int32_t volatile* _destination, int32_t _value)
		{
#if YATM_WIN64_ATOMICS
			return InterlockedExchange((LONG volatile*)_destination, (LONG)_value);
#elif YATM_GCC_ATOMICS
			return __sync_swap_4(_destination, _value);
#endif
		}

		static int64_t interlocked_exchange64(int64_t volatile* _destination, int64_t _value)
		{
#if YATM_WIN64_ATOMICS
			return InterlockedExchange64((LONG64 volatile*)_destination, (LONG64)_value);
#elif YATM_GCC_ATOMICS
			return __sync_swap_8(_destination, _value);
#endif
		}

		static int32_t interlocked_compare_exchange(int32_t volatile* _destination, int32_t _exchange, int32_t _comperand)
		{
#if YATM_WIN64_ATOMICS
			return InterlockedCompareExchange((LONG volatile*)_destination, (LONG)_exchange, (LONG)_comperand);
#elif YATM_GCC_ATOMICS
			return __sync_val_compare_and_swap_4(_destination, _compreand, _exchange);
#endif
		}

		static int64_t interlocked_compare_exchange64(int64_t volatile* _destination, int64_t _exchange, int64_t _comperand)
		{
#if YATM_WIN64_ATOMICS
			return InterlockedCompareExchange64((LONG64 volatile*)_destination, (LONG64)_exchange, (LONG64)_comperand);
#elif YATM_GCC_ATOMICS
			return __sync_val_compare_and_swap_8(_destination, _compreand, _exchange);
#endif
		}

		static void* interlocked_compare_exchange_ptr(void* volatile* _destination, void* _exchange, void* _comperand)
		{
#if YATM_WIN64_ATOMICS
			return InterlockedCompareExchangePointer(_destination, _exchange, _comperand);
#elif YATM_GCC_ATOMICS
			return (void*)__sync_val_compare_and_swap_8((int64_t*)_destination, (int64_t)_compreand, (int64_t)_exchange);
#endif
		}

	private:
#if YATM_WIN64
		static_assert(sizeof(LONG) == sizeof(int32_t));
		static_assert(sizeof(LONG64) == sizeof(int64_t));
#endif
	};

	// -----------------------------------------------------------------------------------------------
	// A representation of an OS mutex.
	// -----------------------------------------------------------------------------------------------
	class mutex : public no_copy_no_move
	{
		friend class condition_var;
	public:
		// -----------------------------------------------------------------------------------------------
		mutex()
		{
#if YATM_WIN64
	#if YATM_USE_RW_LOCKS
			InitializeSRWLock(&m_lock);
	#else
			InitializeCriticalSection(&m_cs);
	#endif // YATM_USE_RW_LOCKS
#elif YATM_USE_PTHREADS
			pthread_mutex_init(&m_pmtx, nullptr);
#endif // YATM_WIN64
		}

		// -----------------------------------------------------------------------------------------------
		~mutex()
		{

#if YATM_WIN64
	#if !YATM_USE_RW_LOCKS
			DeleteCriticalSection(&m_cs);
	#endif // !YATM_USE_RW_LOCKS
#elif YATM_USE_PTHREADS
			pthread_mutex_destroy(&m_pmtx);
#endif // YATM_WIN64
		}

		// -----------------------------------------------------------------------------------------------
		// Lock the mutex, claiming ownership.
		// -----------------------------------------------------------------------------------------------
		void lock()
		{
#if YATM_WIN64
	#if YATM_USE_RW_LOCKS
			AcquireSRWLockExclusive(&m_lock);
	#else
			EnterCriticalSection(&m_cs);
	#endif // YATM_USE_RW_LOCKS
#elif YATM_USE_PTHREADS
			int32_t const errorCode = pthread_mutex_lock(&m_pmtx);
			YATM_ASSERT(errorCode == 0);
#endif // YATM_WIN64
		}

		// -----------------------------------------------------------------------------------------------
		// Unlock the mutex, giving up ownership.
		// -----------------------------------------------------------------------------------------------
		void unlock()
		{
#if YATM_WIN64
#if YATM_USE_RW_LOCKS
			ReleaseSRWLockExclusive(&m_lock);
#else
			LeaveCriticalSection(&m_cs);
#endif // YATM_USE_RW_LOCKS
#elif YATM_USE_PTHREADS
			int32_t const errorCode = pthread_mutex_unlock(&m_pmtx);
			YATM_ASSERT(errorCode == 0);
#endif // YATM_WIN64
		}

		// -----------------------------------------------------------------------------------------------
		// Try to lock the mutex, returning true if it did.
		// -----------------------------------------------------------------------------------------------
		bool try_lock()
		{
			bool v = false;
#if YATM_WIN64
	#if YATM_USE_RW_LOCKS
			v = TryAcquireSRWLockExclusive(&m_lock);
	#else
			v = TryEnterCriticalSection(&m_cs);
	#endif // YATM_USE_RW_LOCKS
#elif YATM_USE_PTHREADS
			v = (pthread_mutex_trylock(&m_pmtx) == 0);
#endif // YATM_WIN64

			return v;
		}

		// -----------------------------------------------------------------------------------------------
		// Lock the mutex (read mode if possible).
		// -----------------------------------------------------------------------------------------------
		void lock_shared()
		{
#if YATM_USE_RW_LOCKS
	#if YATM_WIN64
			AcquireSRWLockShared(&m_lock);
	#endif // YATM_WIN64
#else
			lock();
#endif // YATM_USE_RW_LOCKS
		}

		// -----------------------------------------------------------------------------------------------
		// Try to lock the mutex (read mode if possible), returning true if it did.
		// -----------------------------------------------------------------------------------------------
		bool try_lock_shared()
		{
			bool v = false;
#if YATM_USE_RW_LOCKS
	#if YATM_WIN64
			TryAcquireSRWLockShared(&m_lock);
	#endif // YATM_WIN64
#else
			v = try_lock();
#endif // YATM_USE_RW_LOCKS

			return v;
		}

		// -----------------------------------------------------------------------------------------------
		// Unlock the mutex (read mode if possible).
		// -----------------------------------------------------------------------------------------------
		void unlock_shared()
		{
#if YATM_USE_RW_LOCKS
	#if YATM_WIN64
			ReleaseSRWLockShared(&m_lock);
	#endif // YATM_WIN64
#else
			unlock();
#endif // YATM_USE_RW_LOCKS
		}

	private:
#if YATM_WIN64
	#if YATM_USE_RW_LOCKS
		SRWLOCK m_lock;
	#else
		CRITICAL_SECTION m_cs;
	#endif
#elif YATM_USE_PTHREADS
		pthread_mutex_t m_pmtx;
#endif // YATM_WIN64
	}; 

	// -----------------------------------------------------------------------------------------------
	// A scoped-lock mechanism for mutexes.
	// -----------------------------------------------------------------------------------------------
	template<typename T, bool read_only=false>
	class scoped_lock : public no_copy
	{
		friend class condition_var;
	public:
		// -----------------------------------------------------------------------------------------------
		scoped_lock(T* _mutex) : m_mutex(_mutex)
		{
			lock();
		}

		// -----------------------------------------------------------------------------------------------
		scoped_lock(T& _mutex) : m_mutex(&_mutex)
		{
			lock();
		}

		// -----------------------------------------------------------------------------------------------
		~scoped_lock()
		{
			if constexpr (read_only)
				m_mutex->unlock_shared();
			else
				m_mutex->unlock();
		}

	private:
		void lock()
		{
			if constexpr (read_only)
				m_mutex->lock_shared();
			else
				m_mutex->lock();
		}

		T* m_mutex = nullptr;
	};

	// -----------------------------------------------------------------------------------------------
	// A representation of an OS condition variable.
	// -----------------------------------------------------------------------------------------------
	class condition_var : public no_copy_no_move
	{
	public:
		// -----------------------------------------------------------------------------------------------
		condition_var()
		{
#if YATM_WIN64
			InitializeConditionVariable(&m_cv);
#elif YATM_USE_PTHREADS
			pthread_cond_init(&m_cv, nullptr);
#endif // YATM_WIN64
		}

		// -----------------------------------------------------------------------------------------------
		~condition_var()
		{
#if YATM_USE_PTHREADS
			pthread_cond_destroy(&m_cv);
#endif // YATM_USE_PTHREADS
		}

		// -----------------------------------------------------------------------------------------------
		// Notify all threads waiting on this condition variable.
		// -----------------------------------------------------------------------------------------------
		void notify_all()
		{
#if YATM_WIN64
			WakeAllConditionVariable(&m_cv);
#elif YATM_USE_PTHREADS
			pthread_cond_broadcast(&m_cv);
#endif // YATM_WIN64
		}

		// -----------------------------------------------------------------------------------------------
		// Notify a thread waiting on this condition variable.
		// -----------------------------------------------------------------------------------------------
		void notify_one()
		{
#if YATM_WIN64
			WakeConditionVariable(&m_cv);
#elif YATM_USE_PTHREADS
			pthread_cond_signal(&m_cv);
#endif // YATM_WIN64
		}

		// -----------------------------------------------------------------------------------------------
		// Wait on this condition variable.
		// -----------------------------------------------------------------------------------------------
		template<typename Condition>
		void wait(mutex& _lock, bool read_only, const Condition& _condition)
		{
#if YATM_WIN64
			while (!_condition())
			{
	#if YATM_USE_RW_LOCKS
				SleepConditionVariableSRW(&m_cv, &_lock.m_lock, INFINITE, read_only ? CONDITION_VARIABLE_LOCKMODE_SHARED : 0);
	#else
				SleepConditionVariableCS(&m_cv, &_lock.m_cs, INFINITE);
	#endif // YATM_USE_RW_LOCKS
			}
#elif YATM_USE_PTHREADS
			while (!_condition())
			{
				pthread_cond_wait(&m_cv, &_lock.m_pmtx);
			}
#endif // YATM_WIN64
		}

	private:
#if YATM_WIN64
		CONDITION_VARIABLE m_cv;
#elif YATM_USE_PTHREADS
		pthread_cond_t m_cv;
#endif // YATM_WIN64
	};

	// -----------------------------------------------------------------------------------------------
	// An atomic counter used for synchronisation.
	// -----------------------------------------------------------------------------------------------
	class counter
	{
	public:
		// -----------------------------------------------------------------------------------------------
		counter() : m_value(0xffffffff) { }

		// -----------------------------------------------------------------------------------------------
		counter(const counter&) = delete;
		counter& operator=(const counter&) = delete;

		counter(counter&& other) noexcept
		{
			*this = std::move(other);
		}

		counter& operator=(counter&& other) noexcept
		{
			if (this != &other)
			{
				m_value = other.m_value;
				other.m_value = 0;				
			}
			return *this;
		}

		// -----------------------------------------------------------------------------------------------
		// Checks if the internal atomic counter has not yet been incremented/touched.
		// -----------------------------------------------------------------------------------------------
		bool is_untouched()
		{
			return is_equal(0xffffffff);
		}

		// -----------------------------------------------------------------------------------------------
		// Checks if the internal atomic counter has reached 0.
		// -----------------------------------------------------------------------------------------------
		bool is_done()
		{
			return is_equal(0);
		}

		// -----------------------------------------------------------------------------------------------
		// Checks the internal atomic counter for quality.
		// -----------------------------------------------------------------------------------------------
		bool is_equal(int32_t _value)
		{
			return atomic::interlocked_compare_exchange(&m_value, _value, _value) == _value;
		}

		// -----------------------------------------------------------------------------------------------
		// Increment the internal atomic counter and return its value.
		// -----------------------------------------------------------------------------------------------
		int32_t increment()
		{
			YATM_ASSERT(get_current() < std::numeric_limits<int32_t>::max());
			return atomic::interlocked_increment(&m_value);
		}

		// -----------------------------------------------------------------------------------------------
		// Decrement the internal atomic counter and return its value.
		// -----------------------------------------------------------------------------------------------
		int32_t decrement()
		{
			YATM_ASSERT(get_current() != 0);
			return atomic::interlocked_decrement(&m_value);
		}

		// -----------------------------------------------------------------------------------------------
		// Update the value of the internal atomic counter and return its previous value.
		// -----------------------------------------------------------------------------------------------
		int32_t set(int32_t v)
		{
			return atomic::interlocked_exchange(&m_value, v);
		}

		// -----------------------------------------------------------------------------------------------
		// Returns the current value of the internal atomic counter.
		// -----------------------------------------------------------------------------------------------
		int32_t get_current()
		{
			return atomic::interlocked_compare_exchange(&m_value, 0, 0);
		}

		// -----------------------------------------------------------------------------------------------
		// Initialise the counter to bring it from its original invalid value to 0, if not previously initialised.
		// -----------------------------------------------------------------------------------------------
		void touch()
		{
			atomic::interlocked_compare_exchange(&m_value, 0, 0xffffffff);
		}

	private:
		YATM_ATOMIC_ALIGN int32_t m_value;
	};

	// -----------------------------------------------------------------------------------------------
	// A representation of a TLS member.
	// -----------------------------------------------------------------------------------------------
	template<class T>
	class tls : public no_copy
	{
		static uint32_t const s_invalidTlsIndex = 0xffffffff;
#if YATM_WIN64
		static_assert(s_invalidTlsIndex == TLS_OUT_OF_INDEXES);
#endif

	public:
		// -----------------------------------------------------------------------------------------------
		tls()
		{		
#if YATM_USE_PTHREADS
			if (pthread_key_create(&m_tlsIndex, nullptr) != 0)
			{
				m_tlsIndex = s_invalidTlsIndex;
			}

#elif YATM_WIN64
			m_tlsIndex = TlsAlloc();
#endif // YATM_USE_PTHREADS

			YATM_ASSERT(m_tlsIndex != s_invalidTlsIndex);
		}

		// -----------------------------------------------------------------------------------------------
		~tls()
		{
			if (m_tlsIndex != s_invalidTlsIndex)
			{
#if YATM_USE_PTHREADS
				pthread_key_delete(m_tlsIndex);
#elif YATM_WIN64
				TlsFree(m_tlsIndex);
#endif // YATM_USE_PTHREADS
			}
		}

		// -----------------------------------------------------------------------------------------------
		tls(tls&& other)
		{
			*this = std::move(other);
		}

		// -----------------------------------------------------------------------------------------------
		tls& operator=(tls&& other) noexcept
		{
			if (this != &other)
			{
				m_tlsIndex = other.m_tlsIndex;
				other.m_tlsIndex = s_invalidTlsIndex;
			}
			return *this;
		}

		// -----------------------------------------------------------------------------------------------
		void set(T* const data) const
		{
			YATM_ASSERT(m_tlsIndex != s_invalidTlsIndex);
#if YATM_USE_PTHREADS
			pthread_setspecific(m_tlsIndex, data);
#elif YATM_WIN64
			TlsSetValue(m_tlsIndex, data);
#endif // YATM_USE_PTHREADS
		}

		// -----------------------------------------------------------------------------------------------
		T* const get() const
		{
			YATM_ASSERT(m_tlsIndex != s_invalidTlsIndex);

			T* data = nullptr;
#if YATM_USE_PTHREADS
			data = static_cast<T* const>(pthread_getspecific(m_tlsIndex));
#elif YATM_WIN64			
			data = static_cast<T* const>(TlsGetValue(m_tlsIndex));
#endif // YATM_USE_PTHREADS
			return data;
		}

	private:
#if YATM_USE_PTHREADS
		uint32_t m_tlsIndex;
#elif YATM_WIN64
		DWORD m_tlsIndex;
#endif // YATM_USE_PTHREADS
	};

	// -----------------------------------------------------------------------------------------------
	// Describes a job that the scheduler can run.
	// -----------------------------------------------------------------------------------------------
	struct alignas(YATM_CACHE_LINE_SIZE) job
	{
		enum flags
		{
			JF_None = 0x0,
			JF_Recurring = 0x1
		};

		using JobFuncPtr = std::function<bool(void* const)>;

		JobFuncPtr	m_function;
		void*		m_data;
		counter*	m_counter;
		job*		m_parent;
		uint64_t	m_workerMask;
		counter		m_pendingJobs;
		uint32_t    m_flags;
	};

	// -----------------------------------------------------------------------------------------------
	// A representation of an OS thread.
	// -----------------------------------------------------------------------------------------------
	class thread : public no_copy_no_move
	{
		typedef void(*ThreadEntryPoint)(void*);
	public:
		// -----------------------------------------------------------------------------------------------
		thread()
			:
			m_threadId(0),
			m_stackSizeInBytes(0),
			m_index(0)
#if YATM_WIN64
			, m_handle(nullptr)
#endif // YATM_WIN64
		{

		}

		// -----------------------------------------------------------------------------------------------
		~thread()
		{
#if YATM_WIN64
			if (m_handle != nullptr)
			{
				CloseHandle(m_handle);
			}
#elif YATM_USE_PTHREADS
			pthread_exit(nullptr);
#endif // YATM_WIN64
		}

		// -----------------------------------------------------------------------------------------------
		void create(uint32_t _index, uint32_t _stackSizeInBytes, ThreadEntryPoint _function, void* const _data, thread_priority _priority = thread_priority::normal)
		{
			m_index = _index;
			m_stackSizeInBytes = _stackSizeInBytes;

#if YATM_WIN64
			int32_t win32Priority = THREAD_PRIORITY_NORMAL;
			switch (_priority)
			{
			case thread_priority::lowest:
				win32Priority = THREAD_PRIORITY_LOWEST;
				break;
			case thread_priority::below_normal:
				win32Priority = THREAD_PRIORITY_BELOW_NORMAL;
				break;			
			case thread_priority::above_normal:
				win32Priority = THREAD_PRIORITY_ABOVE_NORMAL;
				break;
			case thread_priority::highest:
				win32Priority = THREAD_PRIORITY_HIGHEST;
				break;
			case thread_priority::time_critical:
				win32Priority = THREAD_PRIORITY_TIME_CRITICAL;
				break;
			default: break;
			}

			m_handle = CreateThread(nullptr, m_stackSizeInBytes, (LPTHREAD_START_ROUTINE)_function, _data, 0, &m_threadId);
			YATM_ASSERT(m_handle != nullptr);
			
			BOOL success = SetThreadPriority(m_handle, win32Priority);
			YATM_ASSERT(success);

			// Update the thread's name.
			// Requires Windows Server 2016, Windows 10 LTSB 2016 and Windows 10 version 1607
			// https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreaddescription
			wchar_t name[64];
			swprintf(name, sizeof(name), L"Worker #%u", _index);
			success = success && SetThreadDescription(m_handle, name);
			YATM_ASSERT(success);

#elif YATM_USE_PTHREADS
            pthread_attr_t attr;
            pthread_attr_init(&attr);
            pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
            pthread_attr_setstacksize (&attr, m_stackSizeInBytes);

			int32_t const errorCode = pthread_create(&m_thread, &attr, (void*(*)(void*))_function, _data);
			YATM_ASSERT(errorCode == 0);

			// Cannot currently name threads on Apple OS; needs to be called from the thread function itself.
			#if !YATM_APPLE
			char name[64];
			sprintf(name, "Worker #%u", _index);
			pthread_setname_np(m_thread.thread, name);
			#endif // !YATM_APPLE

			m_threadId = (uint32_t)m_thread.thread;

			pthread_attr_destroy(&attr);
#endif // YATM_WIN64
		}

		// -----------------------------------------------------------------------------------------------
		void join()
		{
#if YATM_WIN64
			WaitForSingleObject(m_handle, INFINITE);
#elif YATM_USE_PTHREADS
			pthread_join(m_thread, nullptr);
#endif // YATM_WIN64
		}

		// -----------------------------------------------------------------------------------------------
		// Get the thread worker index.
		// -----------------------------------------------------------------------------------------------
		uint32_t get_index() const { return m_index; }

		// -----------------------------------------------------------------------------------------------
		// Get the OS thread index.
		// -----------------------------------------------------------------------------------------------
		uint32_t get_id() const
		{
#if YATM_WIN64
	#if YATM_DEBUG
			DWORD h = GetThreadId(m_handle);
			YATM_ASSERT(h == m_threadId);
	#endif // YATM_DEBUG
			return (uint32_t)m_threadId;
#elif YATM_NIX || YATM_APPLE
			return m_threadId;
#endif // YATM_WIN64
		}

	private:
#if YATM_WIN64
		HANDLE		m_handle;
		DWORD		m_threadId;
#elif YATM_USE_PTHREADS
		pthread_t   m_thread;
		uin64_t     m_threadId;
#endif // YATM_WIN64

		uint32_t	m_stackSizeInBytes;
		uint32_t	m_index;
	};

	// -----------------------------------------------------------------------------------------------
	// A description for the scheduler to create the worker threads.
	// -----------------------------------------------------------------------------------------------
	struct scheduler_desc
	{
		thread_priority* m_priorities;																		// Per thread priorities, the array must be the same size as m_numThreads.
		uint32_t		 m_numThreads;																		// How many threads to use.
		uint32_t		 m_stackSizeInBytes = YATM_DEFAULT_STACK_SIZE;										// Stack size in bytes of each thread.
		uint32_t		 m_jobQueueReservation = YATM_DEFAULT_JOB_QUEUE_RESERVATION;						// How many jobs to reserve in the job vector.
		uint32_t		 m_pendingJobQueueReservation = YATM_DEFAULT_PENDING_JOB_QUEUE_RESERVATION;			// How many jobs to reserve in the pending job vector (jobs waiting to be kicked).
	};
	
	// -----------------------------------------------------------------------------------------------
	// A queue containing jobs to be processed.
	// -----------------------------------------------------------------------------------------------
	class job_queue : public no_copy_no_move
	{
	public:
		job_queue() = default;
		
		// -----------------------------------------------------------------------------------------------
		// Enqueue a job for defer deletion.
		// -----------------------------------------------------------------------------------------------
		void enqueue_free(job* const _job)
		{
			scoped_lock<mutex> lock(&m_mutex);
			m_pendingFree.push(_job);
		}

		// -----------------------------------------------------------------------------------------------
		// Process job free operations.
		// -----------------------------------------------------------------------------------------------
		void free_jobs()
		{
			scoped_lock<mutex> lock(&m_mutex);
			while (!m_pendingFree.empty())
			{
				job* jobFree = m_pendingFree.front();
				YATM_FREE(jobFree);

				m_pendingFree.pop();
			}
		}

		// -----------------------------------------------------------------------------------------------
		// Lock this queue mutex.
		// -----------------------------------------------------------------------------------------------
		void lock()
		{
			m_mutex.lock();
		}

		// -----------------------------------------------------------------------------------------------
		// Attempt to lock this queue mutex.
		// -----------------------------------------------------------------------------------------------
		bool try_lock()
		{
			return m_mutex.try_lock();
		}

		// -----------------------------------------------------------------------------------------------
		// Unlock this queue mutex.
		// -----------------------------------------------------------------------------------------------
		void unlock()
		{
			m_mutex.unlock();
		}

		// -----------------------------------------------------------------------------------------------
		// Lock this queue mutex (read mode).
		// -----------------------------------------------------------------------------------------------
		void lock_shared()
		{
			m_mutex.lock_shared();
		}

		// -----------------------------------------------------------------------------------------------
		// Attempt to lock this queue mutex (read mode).
		// -----------------------------------------------------------------------------------------------
		bool try_lock_shared()
		{
			return m_mutex.try_lock_shared();
		}

		// -----------------------------------------------------------------------------------------------
		// Unlock this queue mutex (read mode).
		// -----------------------------------------------------------------------------------------------
		void unlock_shared()
		{
			m_mutex.unlock_shared();
		}

		// -----------------------------------------------------------------------------------------------
		// Notify the condition variable.
		// -----------------------------------------------------------------------------------------------
		void notify()
		{
			m_cv.notify_one();
		}

		// -----------------------------------------------------------------------------------------------
		// Notify the condition variable (all threads)
		// -----------------------------------------------------------------------------------------------
		void notify_all()
		{
			m_cv.notify_all();
		}

		// -----------------------------------------------------------------------------------------------
		// Set the running state for this queue.
		// -----------------------------------------------------------------------------------------------
		void set_running(bool _running)
		{
			m_isRunning = _running;
		}

		// -----------------------------------------------------------------------------------------------
		// Get the running state for this queue.
		// -----------------------------------------------------------------------------------------------
		bool is_running() const
		{
			return m_isRunning;
		}

		// -----------------------------------------------------------------------------------------------
		// Set the paused state for this queue.
		// -----------------------------------------------------------------------------------------------
		void set_paused(bool _paused)
		{
			m_isPaused = _paused;
		}

		// -----------------------------------------------------------------------------------------------
		// Get the paused state for this queue.
		// -----------------------------------------------------------------------------------------------
		bool is_paused() const
		{
			return m_isPaused;
		}

		// -----------------------------------------------------------------------------------------------
		// Reserve N jobs for this queue.
		// -----------------------------------------------------------------------------------------------
		void reserve(size_t _size)
		{
			m_queue.reserve(_size);
		}

		// -----------------------------------------------------------------------------------------------
		// Get the job at the specified index and remove it from the queue.
		// -----------------------------------------------------------------------------------------------
		job* const get_job(size_t _index)
		{
			YATM_ASSERT(_index < size());
			job* const j = m_queue[_index];
			m_queue.erase(m_queue.begin() + _index);
			return j;
		}

		// -----------------------------------------------------------------------------------------------
		// Get the job at the specified index and remove it from the queue. Similar to get_job, but this time the workerMask is checked against the desired worker index.
		// -----------------------------------------------------------------------------------------------
		job* const get_job(size_t _index, uint64_t _workerIndex)
		{
			YATM_ASSERT(_index < size());
			job* const j = m_queue[_index];

			if ( (j->m_workerMask & (1ull << _workerIndex)) != 0)
			{
				m_queue.erase(m_queue.begin() + _index);
				return j;
			}

			return nullptr;
		}

		// -----------------------------------------------------------------------------------------------
		// Get the job at the specified index, but do not remove it from the queue.
		// -----------------------------------------------------------------------------------------------
		job* const peek_job(size_t _index) const
		{
			YATM_ASSERT(_index < size());
			return m_queue[_index];
		}

		// -----------------------------------------------------------------------------------------------
		// Push a job to the queue.
		// -----------------------------------------------------------------------------------------------
		void push_back(job* const _job)
		{
			m_queue.push_back(_job);
		}

		// -----------------------------------------------------------------------------------------------
		// Perform work stealing from candidate queues.
		// -----------------------------------------------------------------------------------------------
		void steal(job_queue* _candidates, uint64_t _size)
		{
#if YATM_ENABLE_WORK_STEALING
			// If the queue job count is 0, then we can attempt to steal from another queue.
			if (empty())
			{
				for (auto i = 0; i < _size; ++i)
				{
					job_queue& otherQueue = _candidates[i];

					// Skip same queue.
					if (&otherQueue == this)
					{
						continue;
					}

					// Find a compatible job for this queue.
					if (otherQueue.try_lock())
					{
						job* stolen_job = nullptr;
						uint64_t jobIndex = 0ull;
						if (!otherQueue.empty())
						{
							do
							{
								stolen_job = otherQueue.get_job(jobIndex, i);
							} while ((stolen_job == nullptr) && (jobIndex++ < otherQueue.size()));
						}
						otherQueue.unlock();

						if (stolen_job != nullptr)
						{
							push_back(stolen_job);
							break;
						}
					}
				}
			}
#endif // YATM_ENABLE_WORK_STEALING
		}

		// -----------------------------------------------------------------------------------------------
		// Get the current size of the queue.
		// -----------------------------------------------------------------------------------------------
		size_t size() const
		{
			return m_queue.size();
		}

		// -----------------------------------------------------------------------------------------------
		// Check if the queue is empty or not.
		// -----------------------------------------------------------------------------------------------
		bool empty() const
		{
			return size() == 0;
		}

		// -----------------------------------------------------------------------------------------------
		// Wait until the condition is fulfilled.
		// -----------------------------------------------------------------------------------------------
		template<typename T>
		void wait(bool read_only, T _predicate)
		{
			m_cv.wait(m_mutex, read_only, _predicate);
		}

	private:
		std::vector<job*> m_queue;
		std::queue<job*>  m_pendingFree;
		mutex m_mutex;
		condition_var m_cv;

		bool m_isRunning = false;
		bool m_isPaused = false;
	};

	// -----------------------------------------------------------------------------------------------
	// The task scheduler, used to dispatch tasks for consumption by the worker threads.
	// -----------------------------------------------------------------------------------------------
	class scheduler : public no_copy_no_move
	{
	private:
		// -----------------------------------------------------------------------------------------------
		// Used to pass in data when the workers are initialised.
		// -----------------------------------------------------------------------------------------------
		struct worker_thread_data
		{
			yatm::scheduler*	m_scheduler;
			uint32_t			m_id;
		};

		// -----------------------------------------------------------------------------------------------
		// Worker internal
		// -----------------------------------------------------------------------------------------------
		bool worker_internal(job* _job, job_queue& _queue)
		{
			bool isJobFinished = true;

			if (_job != nullptr)
			{
				// Recurring jobs do not leave the queue until the worker function says so.
				bool const isRecurring = (_job->m_flags & job::JF_Recurring) != 0;
				
				// process job
				if (_job->m_function != nullptr)
				{
					isJobFinished = _job->m_function(_job->m_data);
				}

				// Job has finished.
				if (isJobFinished || !isRecurring)
				{
					// decrement the counter
					if (_job->m_counter != nullptr)
					{
						_job->m_counter->decrement();
					}

					// Finish job, notifying parents recursively.
					finish_job(_job, _queue);
				}
				// Job has not finished yet, but we need to re-add it to the queue as it needs to be reprocessed.
				else if (isRecurring)
				{
					_queue.lock();
					_queue.push_back(_job);
					_queue.notify();
					_queue.unlock();					
				}
			}
			
			yield();
			return isJobFinished;
		}

		// -----------------------------------------------------------------------------------------------
		// Get the next available compatible job and remove it from the queue.
		// -----------------------------------------------------------------------------------------------
		job* get_next_job(uint64_t _index)
		{
			job* current_job = nullptr;

			job_queue& queue = m_queues[_index];

			// Find the next job ready to be processed
			for (auto i = 0; i < queue.size(); ++i)
			{
				job* const j = queue.peek_job(i);
				// Can this job be processed by this worker thread?
				if (j->m_workerMask & (1ull << _index))
				{
					// This job has 1 remaining task, which means that all its dependencies have been processed.
					// Pick this task, removing it from the job queue.
					if (j->m_pendingJobs.is_equal(1u))
					{
						current_job = queue.get_job(i);
						break;
					}
				}
			}

			return current_job;
		}

		// -----------------------------------------------------------------------------------------------
		// Worker entry point; pulls jobs from the global queue and processes them.
		// -----------------------------------------------------------------------------------------------
		void worker_entry_point(uint64_t _index)
		{
			YATM_ASSERT(_index < m_queueCount);
			job_queue& queue = m_queues[_index];

			YATM_MALLOC_INIT;

			while (queue.is_running())
			{
				YATM_WORKER_SCOPE("WorkerEntryFunction");
				job* current_job = nullptr;
				{					
					{
						// Wait for this thread to be woken up by the condition variable (there must be at least 1 job in the queue, or perhaps we want to simply stop)
						queue.lock_shared();
						queue.wait(true, [this, &queue] { return !queue.is_paused() && ((queue.size() > 0u) || !queue.is_running()); });
						
						queue.steal(m_queues, m_queueCount);

						current_job = get_next_job(_index);
						queue.unlock_shared();
					}
				}

				worker_internal(current_job, queue);
			}

			YATM_MALLOC_DEINIT;

#if YATM_USE_PTHREADS
			pthread_exit(nullptr);
#endif // YATM_USE_PTHREADS
		}

	public:
		// -----------------------------------------------------------------------------------------------
		scheduler() :
			m_threads(nullptr)
		{

#if YATM_WIN64
			SYSTEM_INFO info;
			ZeroMemory(&info, sizeof(info));
			GetSystemInfo(&info);
			m_hwConcurency = info.dwNumberOfProcessors;
#elif YATM_NIX || YATM_APPLE
			m_hwConcurency = sysconf(_SC_NPROCESSORS_CONF);
#endif // YATM_WIN64
		}

		// -----------------------------------------------------------------------------------------------
		~scheduler()
		{
			set_running(false);

			// wait for workers to finish
			join();

			// free thread data array
			delete[] m_threadData;
			m_threadData = nullptr;

			// free the thread array
			delete[] m_threads;
			m_threads = nullptr;

			delete[] m_queues;
			m_queues = nullptr;
		}

		// -----------------------------------------------------------------------------------------------
		// Free any memory allocations that are no longer needed. This needs to be done at the start of the next iteration.
		// -----------------------------------------------------------------------------------------------
		void reset()
		{
			for (uint32_t i = 0; i < m_queueCount; ++i)
			{
				job_queue& queue = m_queues[i];
				queue.free_jobs();
			}
		}

		// -----------------------------------------------------------------------------------------------
		// Initialise the scheduler.
		// -----------------------------------------------------------------------------------------------
		void init(const scheduler_desc& _desc)
		{
			m_numThreads = std::max(1u, std::min<uint32_t>(_desc.m_numThreads, get_max_threads()));

			m_threadData = new worker_thread_data[m_numThreads];
			for (uint32_t i = 0; i < m_numThreads; ++i)
			{
				m_threadData[i].m_scheduler = this;
				m_threadData[i].m_id = i;
			}

			m_queueCount = m_numThreads;
			m_queues = new job_queue[m_queueCount];

			m_stackSizeInBytes = (uint32_t)align(_desc.m_stackSizeInBytes > 0 ? (uint64_t)_desc.m_stackSizeInBytes : YATM_DEFAULT_STACK_SIZE, 16ull);

			m_threads = new thread[m_numThreads];

			// reserve some space in the global job queue
			for (uint32_t i = 0; i < m_queueCount; ++i)
			{
				m_queues[i].reserve(_desc.m_jobQueueReservation);
			}

			// reserve some space in the currently pending job queue
			m_pendingJobsToAdd.reserve(_desc.m_pendingJobQueueReservation);

			// enable the scheduler and let its workers run
			set_running(true);
			set_paused(false);

			thread_priority* priorities = (thread_priority*)YATM_ALLOCA(sizeof(thread_priority) * m_numThreads);
			if (_desc.m_priorities != nullptr)
			{
				memcpy(priorities, _desc.m_priorities, sizeof(thread_priority) * m_numThreads);
			}
			else
			{
				std::fill(priorities, priorities + m_numThreads, thread_priority::normal);
			}

			// Create N worker threads and kick them off.
			// Each worker will process the next available job item from the global queue, resolve its dependencies and carry on until no jobs are left.
			for (uint32_t i = 0; i < m_numThreads; ++i)
			{
				auto func = [](void* data) -> void
				{
					worker_thread_data* d = reinterpret_cast<worker_thread_data*>(data);
					d->m_scheduler->worker_entry_point(d->m_id);
				};

				m_threads[i].create(i, m_stackSizeInBytes, func, &m_threadData[i], priorities[i]);
			}

			YATM_FREEA(priorities);
		}

		// -----------------------------------------------------------------------------------------------
		// Create a new job.
		// -----------------------------------------------------------------------------------------------
		template<typename Function>
		job* const create_job(Function&& _function, void* const _data, counter* _counter, uint64_t i_workerMask = ~0ull, job::flags _flags = job::JF_None)
		{
			job* const j = allocate<job>();

			j->m_function = std::forward<Function>(_function);
			j->m_data = _data;
			j->m_parent = nullptr;
			j->m_counter = _counter;
			j->m_workerMask = i_workerMask;
			j->m_flags = _flags;

			// Initialise the job with 1 pending job (itself).
			// Adding dependencies increments the pending counter, resolving dependencies decrements it.
			j->m_pendingJobs.touch();
			j->m_pendingJobs.increment();

			// Register this newly created job; all jobs are automatically added when the scheduler kicks-off the tasks.
			scoped_lock<mutex> lock(&m_pendingJobsMutex);
			m_pendingJobsToAdd.push_back(j);			
			return j;
		}

		// -----------------------------------------------------------------------------------------------
		// Create a group. A group is simply a job without any work to be done, used as a dependency in other
		// jobs to create a hierarchy of tasks.
		// -----------------------------------------------------------------------------------------------
		job* const create_group(job* const _parent = nullptr)
		{
			job* const group = create_job(nullptr, nullptr, nullptr);

			// If a parent is specified, setup this dependency
			if (_parent != nullptr)
			{
				depend(_parent, group);
			}

			return group;
		}

		// -----------------------------------------------------------------------------------------------
		// Allocate memory.
		// -----------------------------------------------------------------------------------------------
		template<typename T>
		T* allocate(uint64_t _count, uint64_t _alignment = 16u)
		{
			void* const mem = YATM_ALLOC_COUNT(T, _count, _alignment);
			return new(mem) T[_count];
		}

		// -----------------------------------------------------------------------------------------------
		// Allocate memory.
		// -----------------------------------------------------------------------------------------------
		template<typename T>
		T* allocate(uint64_t _alignment = 16u)
		{
			void* const mem = YATM_ALLOC(T, _alignment);
			return new(mem)T;
		}

		// -----------------------------------------------------------------------------------------------
		// Free previously allocated memory.
		// -----------------------------------------------------------------------------------------------
		void free_alloc(void* const _ptr)
		{
			YATM_FREE(_ptr);
		}

		// -----------------------------------------------------------------------------------------------
		// Adds a job dependency on the specified job.
		// -----------------------------------------------------------------------------------------------
		void depend(job* const _target, job* const _dependency)
		{
			YATM_ASSERT(_dependency->m_parent == nullptr);

			_dependency->m_parent = _target;
			_target->m_pendingJobs.increment();
		}

		// -----------------------------------------------------------------------------------------------
		// Creates a parallel for loop for the specified collection, launching _function per iteration.
		// Blocks until all are complete.
		// -----------------------------------------------------------------------------------------------
		template<typename Iterator, typename Function>
		void parallel_for(const Iterator& _begin, const Iterator& _end, Function&& _function, size_t max_jobs = get_max_threads())
		{
			const auto n = std::distance(_begin, _end);
			if (n <= 0) return;

			// When there is only 1 job, don't pass it through the scheduler.
			if (n == 1)
			{
				_function(&(*(_begin)));
			}
			// Otherwise split into chunks and spawn M amount of jobs.
			else				
			{
				size_t const m = std::min(static_cast<size_t>(n), max_jobs);
				size_t const block_size = std::max(static_cast<size_t>(1u), (n + m - 1) / m);

				counter jobs_done;
				for (auto i=0; i<m; ++i)
				{
					size_t const start = i * block_size;
					size_t const end = std::min(start + block_size, static_cast<size_t>(n));
					if (start >= n)
						continue;
					
					create_job([=](void* const data)
					{
						for (auto job_index=start; job_index != end; ++job_index)
						{
							_function(&(*(_begin + job_index)));
						}
						return true;
					}, nullptr, &jobs_done);										
				}

				kick();
				wait(&jobs_done);
			}
		}

		// -----------------------------------------------------------------------------------------------
		// Signal the worker threads that work has been added.
		// -----------------------------------------------------------------------------------------------
		void kick()
		{
			// Add the pending jobs to the global job queue and notify the worker threads that work has been added.
			{
				scoped_lock<mutex> lock(&m_pendingJobsMutex);
				for (auto& job : m_pendingJobsToAdd)
				{
					add_job(job);
				}
				m_pendingJobsToAdd.clear();
			}

			for (uint32_t i = 0; i < m_queueCount; ++i)
			{
				m_queues[i].notify();
			}
		}

		// -----------------------------------------------------------------------------------------------
		// Try to process the job on a compatible worker thread.
		// -----------------------------------------------------------------------------------------------
		void process_single_job()
		{			
			auto const index = random(0u, m_queueCount-1);

			// Find compatible job to process
			if (m_queues[index].try_lock())
			{
				job* current_job = get_next_job(index);
				m_queues[index].unlock();

				worker_internal(current_job, m_queues[index]);
			}
			yield();						
		}

		// -----------------------------------------------------------------------------------------------
		// Wait for a single job to complete. In the meantime, try to process one pending job.
		// -----------------------------------------------------------------------------------------------
		void wait(job* const _job)
		{
			YATM_ASSERT(_job != nullptr);
			while (!_job->m_pendingJobs.is_done())
			{
				process_single_job();
			}
		}

		// -----------------------------------------------------------------------------------------------
		// Wait for a counter to reach 0. In the meantime, try to process one pending job.
		// -----------------------------------------------------------------------------------------------
		void wait(counter* const _counter)
		{
			YATM_ASSERT(_counter != nullptr);
			while (!_counter->is_done())
			{
				// Process jobs while waiting
				process_single_job();
			}
		}

		// -----------------------------------------------------------------------------------------------
		// Get the current thread id.
		// -----------------------------------------------------------------------------------------------
		uint32_t get_current_thread_id() const
		{
#if YATM_WIN64
			return GetCurrentThreadId();
#elif YATM_USE_PTHREADS
			pthread_id_np_t tid;
			pthread_t const self = pthread_self();
			pthread_getunique_np(&self, &tid);
			return tid;
#endif // YATM_WIN64
		}

		// -----------------------------------------------------------------------------------------------
		// Yield the current thread and allow others to execute.
		// -----------------------------------------------------------------------------------------------
		void yield()
		{
#if YATM_WIN64
			SwitchToThread();
#elif YATM_NIX
			pthread_yield();
#elif YATM_APPLE
			sched_yield();
#endif // YATM_WIN64
		}

		// -----------------------------------------------------------------------------------------------
		// Return the maximum number of worker threads.
		// -----------------------------------------------------------------------------------------------
		uint32_t get_max_threads() const { return m_hwConcurency; }

		// -----------------------------------------------------------------------------------------------
		// Check if the scheduler is running worker functions.
		// -----------------------------------------------------------------------------------------------
		bool is_running() const { return m_isRunning; }

		// -----------------------------------------------------------------------------------------------
		// Stop the scheduler from processing, effectively shutting it down.
		// -----------------------------------------------------------------------------------------------
		void set_running(bool _running)
		{
			m_isRunning = _running;
			for (uint32_t i = 0; i < m_queueCount; ++i)
			{
				m_queues[i].lock();
				m_queues[i].set_running(_running);
				m_queues[i].notify();
				m_queues[i].unlock();
			}
		}

		// -----------------------------------------------------------------------------------------------
		// Check if the scheduler is paused.
		// -----------------------------------------------------------------------------------------------
		bool is_paused() const { return m_isPaused; }

		// -----------------------------------------------------------------------------------------------
		// Set the paused status of the scheduler. Worker threads will not process anything until status is resumed.
		// -----------------------------------------------------------------------------------------------
		void set_paused(bool _paused)
		{
			m_isPaused = _paused;
			for (uint32_t i = 0; i < m_queueCount; ++i)
			{
				m_queues[i].lock();
				m_queues[i].set_paused(_paused);
				m_queues[i].notify();
				m_queues[i].unlock();
			}
		}

		// -----------------------------------------------------------------------------------------------
		// Allow the current thread to sleep for specified duration in ms.
		// -----------------------------------------------------------------------------------------------
		void sleep(uint32_t ms)
		{
#if YATM_WIN64
			Sleep(ms);
#elif YATM_NIX || YATM_APPLE
			usleep(ms * 1000);
#endif // YATM_WIN64
		}

		// -----------------------------------------------------------------------------------------------
		// Wait for all the worker threads to stop executing, block the main thread.
		// -----------------------------------------------------------------------------------------------
		void join()
		{
			YATM_ASSERT(m_threads != nullptr);
			for (uint32_t i = 0; i < m_numThreads; ++i)
			{
				m_threads[i].join();
			}
		}

	private:		
		mutex					m_pendingJobsMutex;
		uint32_t				m_stackSizeInBytes;
		uint32_t				m_hwConcurency;
		uint32_t				m_numThreads;
		uint32_t				m_queueCount;
		worker_thread_data*		m_threadData;
		bool					m_isRunning;
		bool					m_isPaused;		
		thread*					m_threads;
		job_queue*				m_queues;
		std::vector<job*>		m_pendingJobsToAdd;

		// -----------------------------------------------------------------------------------------------
		// Adds a single job item to a scheduler's compatible queue (eg. one that matches the worker mask of the job). Assumes the caller ensures thread safety.
		// -----------------------------------------------------------------------------------------------
		void add_job(job* const _job)
		{
			YATM_ASSERT(_job != nullptr);

			// Find a random compatible queue for the job's worker mask.
			job_queue** queues = (job_queue**)YATM_ALLOCA(sizeof(job_queue*) * m_queueCount);
			uint32_t compatibleQueueCount = 0u;
			for (uint32_t i = 0; i < m_queueCount; ++i)
			{
				auto& queue = m_queues[i];
				if (_job->m_workerMask & (1ull << i))
				{
					queues[compatibleQueueCount++] = &queue;
				}
			}

			YATM_ASSERT(compatibleQueueCount != 0);

			if (compatibleQueueCount > 0)
			{
				uint32_t const index = random(0u, compatibleQueueCount-1);
				auto* queue = queues[index];

				if (_job->m_counter != nullptr)
				{
					_job->m_counter->touch();
					_job->m_counter->increment();
				}

				queue->lock();
				queue->push_back(_job);
				queue->unlock();
			}

			YATM_FREEA(queues);
		}

		// -----------------------------------------------------------------------------------------------
		// Mark this job as finished by decrementing the pendingJobs counter and inform its parents recursively.
		// -----------------------------------------------------------------------------------------------
		void finish_job(job* const _job, job_queue& _queue)
		{
			if (_job != nullptr)
			{
				// Job has finished;
				if (_job->m_pendingJobs.decrement() == 0)
				{
					// Inform the parent.
					finish_job(_job->m_parent, _queue);

					// And add the job to the queue's deferred memory free queue. This happens on the original thread's queue post-stealing, so there is no need to lock it and is thread safe.
					_queue.enqueue_free(_job);
				}
			}
		}
	};
}
