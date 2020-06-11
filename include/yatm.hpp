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
#include <atomic>
#include <algorithm>
#include <cstdlib>
#include <cassert>
#include <functional>
#include <algorithm>
#include <limits.h>
#include <memory.h>
#include <random>

#ifndef YATM_ENABLE_WORK_STEALING
	#define YATM_ENABLE_WORK_STEALING (0u)
#endif // YATM_ENABLE_WORK_STEALING

#ifndef YATM_CACHE_LINE_SIZE
	#define YATM_CACHE_LINE_SIZE (64u)
#endif // YATM_CACHE_SIZE

#ifndef YATM_DEFAULT_STACK_SIZE
	#define YATM_DEFAULT_STACK_SIZE (1024u * 1024u)
#endif // YATM_DEFAULT_STACK_SIZE

#ifndef YATM_DEFAULT_JOB_SCRATCH_BUFFER_SIZE
	#define YATM_DEFAULT_JOB_SCRATCH_BUFFER_SIZE (128u * 1024u)
#endif // YATM_DEFAULT_STACK_SIZE

#ifndef YATM_MAX_WORKER_MASK_STACK_DEPTH
	#define YATM_MAX_WORKER_MASK_STACK_DEPTH (64u)
#endif // YATM_MAX_WORKER_MASK_STACK_DEPTH

#ifndef YATM_ASSERT
	#define YATM_ASSERT(x) assert((x))
#endif // YATM_ASSERT

#ifndef YATM_TTY
	#define YATM_TTY(x) std::cout << (x) << std::endl
#endif // YATM_TTY

#ifndef YATM_DEBUG
	#ifdef _MSC_VER
		#define YATM_DEBUG (_DEBUG)
	#endif //_MSC_VER
#endif // YATM_DEBUG

// When STD_THREAD is defined, undef platform_specific.
#if YATM_STD_THREAD
#undef YATM_WIN64
#undef YATM_LINUX
#endif // YATM_STD_THREAD

#if YATM_WIN64
	#define NOMINMAX
	#define WIN32_LEAN_AND_MEAN
	#include <Windows.h>
#elif YATM_LINUX
	#include <unistd.h>
#elif YATM_STD_THREAD
	#include <thread>
	#include <condition_variable>
	#include <atomic>
	#include <chrono>
#endif // YATM_WIN64

#define YATM_USE_PTHREADS (YATM_LINUX)

#if YATM_USE_PTHREADS
	#include <pthread.h>
#endif // YATM_USE_PTHREADS

// Some defaults for reserving space in the job queues

#ifndef YATM_DEFAULT_JOB_QUEUE_RESERVATION
	#define YATM_DEFAULT_JOB_QUEUE_RESERVATION (1024u)
#endif // YATM_DEFAULT_JOB_QUEUE_RESERVATION

#ifndef YATM_DEFAULT_PENDING_JOB_QUEUE_RESERVATION
	#define YATM_DEFAULT_PENDING_JOB_QUEUE_RESERVATION (128u)
#endif // YATM_DEFAULT_PENDING_JOB_QUEUE_RESERVATION

namespace yatm
{
	static_assert(sizeof(void*) == 8, "Only 64bit platforms are currently supported");

	// -----------------------------------------------------------------------------------------------
	// std::bind wrapped, used specifically for the job callbacks.
	// -----------------------------------------------------------------------------------------------
	template<typename Fx, typename... Args>
	static auto bind(Fx&& _function, Args&&... _args)
	{
		return std::bind(std::forward<Fx>(_function), std::forward<Args>(_args)..., std::placeholders::_1);
	}

	// -----------------------------------------------------------------------------------------------
	// Align input to the next specified alignment.
	// -----------------------------------------------------------------------------------------------
	static size_t align(size_t _value, size_t _align)
	{
		return (_value + (_align - 1)) & ~(_align - 1);
	}

	// -----------------------------------------------------------------------------------------------
	// Align pointer to the next specified alignment.
	// -----------------------------------------------------------------------------------------------
	static uint8_t* align_ptr(uint8_t* _ptr, size_t _align)
	{
		return (uint8_t*)align((size_t)_ptr, _align);
	}

	// -----------------------------------------------------------------------------------------------
	// A representation of an OS mutex.
	// -----------------------------------------------------------------------------------------------
	class mutex
	{
		friend class condition_var;
	public:
		// -----------------------------------------------------------------------------------------------
		mutex()
		{
#if YATM_WIN64
			InitializeCriticalSection(&m_cs);
#elif YATM_USE_PTHREADS
			pthread_mutex_init(&m_pmtx, nullptr);
#endif // YATM_WIN64
		}

		// -----------------------------------------------------------------------------------------------
		mutex(const mutex&) = delete;
		mutex operator=(const mutex&) = delete;

		// -----------------------------------------------------------------------------------------------
		~mutex()
		{

#if YATM_WIN64
			DeleteCriticalSection(&m_cs);
#elif YATM_USE_PTHREADS
			pthread_mutex_destroy(&m_pmtx);
#endif // YATM_WIN64
		}

		// -----------------------------------------------------------------------------------------------
		// Lock the mutex, claiming ownership.
		// -----------------------------------------------------------------------------------------------
		void lock()
		{
#if YATM_STD_THREAD
			m_mutex.lock();
#elif YATM_WIN64
			EnterCriticalSection(&m_cs);
#elif YATM_USE_PTHREADS
			int32_t const errorCode = pthread_mutex_lock(&m_pmtx);
			YATM_ASSERT(errorCode == 0);
#endif // YATM_STD_THREAD
		}

		// -----------------------------------------------------------------------------------------------
		// Try to lock the mutex, returning true if it did.
		// -----------------------------------------------------------------------------------------------
		bool try_lock()
		{
			bool v = false;
#if YATM_STD_THREAD
			v = m_mutex.try_lock();
#elif YATM_WIN64
			v = TryEnterCriticalSection(&m_cs);
#elif YATM_USE_PTHREADS
			v = (pthread_mutex_trylock(&m_pmtx) == 0);
#endif // YATM_STD_THREAD

			return v;
		}

		// -----------------------------------------------------------------------------------------------
		// Unlock the mutex, giving-up ownership.
		// -----------------------------------------------------------------------------------------------
		void unlock()
		{
#if YATM_STD_THREAD
			m_mutex.unlock();
#elif YATM_WIN64
			LeaveCriticalSection(&m_cs);
#elif YATM_USE_PTHREADS
			int32_t const errorCode = pthread_mutex_unlock(&m_pmtx);
			YATM_ASSERT(errorCode == 0);
#endif // YATM_STD_THREAD
		}

	private:
#if YATM_STD_THREAD
		std::mutex m_mutex;
#elif YATM_WIN64
		CRITICAL_SECTION m_cs;
#elif YATM_USE_PTHREADS
		pthread_mutex_t m_pmtx;
#endif // YATM_STD_THREAD
	};

	// -----------------------------------------------------------------------------------------------
	// A scoped-lock mechanism for mutexes.
	// -----------------------------------------------------------------------------------------------
	template<typename T>
	class scoped_lock
	{
		friend class condition_var;
	public:
		// -----------------------------------------------------------------------------------------------
		scoped_lock(T* _mutex) : m_mutex(_mutex), m_locked(false)
		{
			lock();
		}

		// -----------------------------------------------------------------------------------------------
		~scoped_lock()
		{
			unlock();
		}

		// -----------------------------------------------------------------------------------------------
		scoped_lock(const scoped_lock&) = delete;
		scoped_lock& operator=(const scoped_lock&) = delete;

		// -----------------------------------------------------------------------------------------------
		void lock()
		{
			if (!m_locked)
			{
				m_mutex->lock();
			}
			m_locked = true;
		}

		// -----------------------------------------------------------------------------------------------
		void unlock()
		{
			if (m_locked)
			{
				m_mutex->unlock();
			}
			m_locked = false;
		}

	private:
		bool m_locked;
		T* m_mutex;
	};

	// -----------------------------------------------------------------------------------------------
	// A representation of an OS condition variable.
	// -----------------------------------------------------------------------------------------------
	class condition_var
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
#if YATM_WIN64

#elif YATM_USE_PTHREADS
			pthread_cond_destroy(&m_cv);
#endif // YATM_WIN64
		}

		// -----------------------------------------------------------------------------------------------
		condition_var(const condition_var&) = delete;
		condition_var& operator=(const condition_var&) = delete;

		// -----------------------------------------------------------------------------------------------
		// Notify all threads waiting on this condition variable.
		// -----------------------------------------------------------------------------------------------
		void notify_all()
		{
#if YATM_STD_THREAD
			m_cv.notify_all();
#elif YATM_WIN64
			WakeAllConditionVariable(&m_cv);
#elif YATM_USE_PTHREADS
			pthread_cond_broadcast(&m_cv);
#endif // YATM_STD_THREAD
		}

		// -----------------------------------------------------------------------------------------------
		// Notify a thread waiting on this condition variable.
		// -----------------------------------------------------------------------------------------------
		void notify_one()
		{
#if YATM_STD_THREAD
			m_cv.notify_one();
#elif YATM_WIN64
			WakeConditionVariable(&m_cv);
#elif YATM_USE_PTHREADS
			pthread_cond_signal(&m_cv);
#endif // YATM_STD_THREAD
		}

		// -----------------------------------------------------------------------------------------------
		// Wait on this condition variable.
		// -----------------------------------------------------------------------------------------------
		template<typename Condition>
		void wait(scoped_lock<mutex>& _lock, const Condition& _condition)
		{
#if YATM_STD_THREAD
			m_cv.wait(_lock, _condition);
#elif YATM_WIN64
			while (!_condition())
			{
				SleepConditionVariableCS(&m_cv, &_lock.m_mutex->m_cs, INFINITE);
			}
#elif YATM_USE_PTHREADS
			while (!_condition())
			{
					pthread_cond_wait(&m_cv, &_lock.m_mutex->m_pmtx);
			}
#endif // YATM_STD_THREAD
		}

	private:
#if YATM_STD_THREAD
		std::condition_variable_any m_cv;
#elif YATM_WIN64
		CONDITION_VARIABLE m_cv;
#elif YATM_USE_PTHREADS
		pthread_cond_t m_cv;
#endif // YATM_STD_THREAD
	};

	// -----------------------------------------------------------------------------------------------
	// An atomic counter used for synchronisation.
	// -----------------------------------------------------------------------------------------------
	class counter
	{
	public:
		// -----------------------------------------------------------------------------------------------
		counter()
		{
			m_value = 0u;
		}

		// -----------------------------------------------------------------------------------------------
		counter(const counter&) = delete;
		counter& operator=(const counter&) = delete;

		// -----------------------------------------------------------------------------------------------
		// Checks if the internal atomic counter has reached 0.
		// -----------------------------------------------------------------------------------------------
		bool is_done()
		{
			uint32_t expected = 0u;
#if YATM_STD_THREAD || YATM_USE_PTHREADS
			return m_value.compare_exchange_strong(expected, get_current());
#elif YATM_WIN64
			return m_value == expected;
#endif // YATM_STD_THREAD
		}

		// -----------------------------------------------------------------------------------------------
		// Checks the internal atomic counter for quality.
		// -----------------------------------------------------------------------------------------------
		bool is_equal(uint32_t _value)
		{
#if YATM_STD_THREAD || YATM_USE_PTHREADS
			return m_value.compare_exchange_strong(_value, get_current());
#elif YATM_WIN64
			return _value == m_value;
#endif // YATM_STD_THREAD
		}

		// -----------------------------------------------------------------------------------------------
		// Increment the internal atomic counter and return its value.
		// -----------------------------------------------------------------------------------------------
		uint32_t increment()
		{
			YATM_ASSERT(get_current() < UINT_MAX);
#if YATM_STD_THREAD || YATM_USE_PTHREADS
			return ++m_value;
#elif YATM_WIN64
			return InterlockedIncrement(&m_value);
#endif // YATM_STD_THREAD
		}

		// -----------------------------------------------------------------------------------------------
		// Decrement the internal atomic counter and return its value.
		// -----------------------------------------------------------------------------------------------
		uint32_t decrement()
		{
			YATM_ASSERT(get_current() != 0);
#if YATM_STD_THREAD || YATM_USE_PTHREADS
			return --m_value;
#elif YATM_WIN64
			return InterlockedDecrement(&m_value);
#endif // YATM_STD_THREAD
		}

		// -----------------------------------------------------------------------------------------------
		// Returns the current value of the internal atomic counter.
		// -----------------------------------------------------------------------------------------------
		uint32_t get_current() const
		{
#if YATM_STD_THREAD || YATM_USE_PTHREADS
			return m_value.load();
#elif YATM_WIN64
			return m_value;
#endif // YATM_STD_THREAD
		}

	private:
#if YATM_STD_THREAD || YATM_USE_PTHREADS
		std::atomic_uint32_t m_value;
#elif YATM_WIN64
		LONG m_value;
#endif // YATM_STD_THREAD
	};

	// -----------------------------------------------------------------------------------------------
	// Describes a job that the scheduler can run.
	// -----------------------------------------------------------------------------------------------
	struct alignas(YATM_CACHE_LINE_SIZE) job
	{
		using JobFuncPtr = std::function<void(void* const)>;

		JobFuncPtr	m_function;
		void*		m_data;
		counter*	m_counter;
		job*		m_parent;
		uint32_t	m_workerMask;
		counter		m_pendingJobs;
	};

	// -----------------------------------------------------------------------------------------------
	// A representation of an OS thread.
	// -----------------------------------------------------------------------------------------------
	class thread
	{
		typedef void(*ThreadEntryPoint)(void*);
	public:
		// -----------------------------------------------------------------------------------------------
		thread()
			:
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
				TerminateThread(m_handle, 0u);
			}
#elif YATM_USE_PTHREADS
			pthread_exit(nullptr);
#endif // YATM_WIN64
		}

		// -----------------------------------------------------------------------------------------------
		thread(const thread&) = delete;
		thread& operator=(const thread&) = delete;

		// -----------------------------------------------------------------------------------------------
		void create(uint32_t _index, size_t _stackSizeInBytes, ThreadEntryPoint _function, void* const _data)
		{
			m_index = _index;
			m_stackSizeInBytes = _stackSizeInBytes;

#if YATM_STD_THREAD
			m_thread = std::thread(_function, _data);
#elif YATM_WIN64
			m_handle = CreateThread(nullptr, m_stackSizeInBytes, (LPTHREAD_START_ROUTINE)_function, _data, 0, &m_threadId);
			YATM_ASSERT(m_handle != nullptr);
#elif YATM_USE_PTHREADS
			int32_t const errorCode = pthread_create(&m_thread, nullptr, (void*(*)(void*))_function, _data);
			YATM_ASSERT(errorCode == 0);
#endif // YATM_STD_THREAD
		}

		// -----------------------------------------------------------------------------------------------
		void join()
		{
#if YATM_STD_THREAD
			YATM_ASSERT(m_thread.joinable());
			m_thread.join();
#elif YATM_WIN64
			WaitForSingleObject(m_handle, INFINITE);
#elif YATM_USE_PTHREADS
			pthread_join(m_thread, nullptr);
#endif // YATM_STD_THREAD
		}

		// -----------------------------------------------------------------------------------------------
		// Get the thread worker index.
		// -----------------------------------------------------------------------------------------------
		uint32_t get_index() const { return m_index; }

		// -----------------------------------------------------------------------------------------------
		// Get the OS thread index.
		// -----------------------------------------------------------------------------------------------
		size_t get_id() const
		{
#if YATM_STD_THREAD
			std::hash<std::thread::id> h;
			return h(m_thread.get_id());
#elif YATM_WIN64
	#if YATM_DEBUG
			DWORD h = GetThreadId(m_handle);
			YATM_ASSERT(h == m_threadId);
	#endif // YATM_DEBUG
			return (size_t)m_threadId;
#elif YATM_LINUX
			return m_threadId;
#endif // YATM_STD_THREAD
		}

	private:
#if YATM_STD_THREAD
		std::thread m_thread;
#elif YATM_WIN64
		HANDLE		m_handle;
		DWORD		m_threadId;
#elif YATM_USE_PTHREADS
		pthread_t m_thread;
		uint32_t  m_threadId;
#endif // YATM_STD_THREAD

		size_t		m_stackSizeInBytes;
		uint32_t	m_index;
	};

	// -----------------------------------------------------------------------------------------------
	// A description for the scheduler to create the worker threads.
	// -----------------------------------------------------------------------------------------------
	struct scheduler_desc
	{
		uint32_t*	m_threadIds;																		// Thread IDs, used to bind jobs to group of threads. Size must match m_numThreads and is initialised to defaults if not specified.
		uint32_t	m_numThreads;																		// How many threads to use.
		uint32_t	m_stackSizeInBytes = YATM_DEFAULT_STACK_SIZE;										// Stack size in bytes of each thread (unsupported in YATM_STD_THREAD).
		uint32_t	m_jobScratchBufferInBytes = YATM_DEFAULT_JOB_SCRATCH_BUFFER_SIZE;					// Size in bytes of the internal scratch allocator. This is used to allocate jobs and job data.
		uint32_t	m_jobQueueReservation = YATM_DEFAULT_JOB_QUEUE_RESERVATION;							// How many jobs to reserve in the job vector.
		uint32_t	m_pendingJobQueueReservation = YATM_DEFAULT_PENDING_JOB_QUEUE_RESERVATION;			// How many jobs to reserve in the pending job vector (jobs waiting to be kicked).
	};

	// -----------------------------------------------------------------------------------------------
	// The task scheduler, used to dispatch tasks for consumption by the worker threads.
	// -----------------------------------------------------------------------------------------------
	class scheduler
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
		bool worker_internal(std::vector<job*>& _queue, uint32_t _index, job* _job)
		{
			if (_job != nullptr)
			{
				// process job
				if (_job->m_function != nullptr)
				{
					_job->m_function(_job->m_data);
				}

				// decrement the counter
				if (_job->m_counter != nullptr)
				{
					_job->m_counter->decrement();
				}

				// Finish job, notifying parents recursively.
				finish_job(_job);
			}
			else
			{
				// No jobs, simply yield.
				yield();
			}

			return (_job != nullptr);
		}

		// -----------------------------------------------------------------------------------------------
		// Worker entry point; pulls jobs from the global queue and processes them.
		// -----------------------------------------------------------------------------------------------
		void worker_entry_point(uint32_t _index)
		{
			while (m_isRunning)
			{
				YATM_ASSERT(_index < m_queueCount);
				std::vector<job*>& queue = m_jobQueue[_index];
				job* current_job = nullptr;
				{
					scoped_lock<mutex> lock(&m_queueMutex);

#if YATM_ENABLE_WORK_STEALING
					// If the queue job count is 0, then we can attempt to steal from another queue.
					if (queue.size() == 0)
					{
						for (uint32_t i = 0; i < m_queueCount; ++i)
						{
							// Skip empty queues and same index
							if ((_index == i) || (m_jobQueue[i].size() == 0))
							{
								continue;
							}

							// Not able to steal because the job is meant to run on a specific thread? skip
							std::vector<job*>& otherQueue = m_jobQueue[i];
							auto it = std::find_if(otherQueue.begin(), otherQueue.end(), [_index](job* j)
							{
								return (j->m_workerMask & (1u << _index)) != 0;
							});

							if (it != otherQueue.end())
							{
								queue.push_back(*it);
								otherQueue.erase(it);
								break;
							}
						}
					}
#endif // YATM_ENABLE_WORK_STEALING

					// Wait for this thread to be woken up by the condition variable (there must be at least 1 job in the queue, or perhaps we want to simply stop)
					m_queueConditionVar.wait(lock, [this, &queue] { return !is_paused() && ((queue.size() > 0u) || !is_running()); });

					// Find the next job ready to be processed
					for (uint32_t i = 0; i < queue.size(); ++i)
					{
						job* j = queue[i];
						// Can this job be processed by this worker thread?
						if (j->m_workerMask & (1u << _index))
						{
							// This job has 1 remaining task, which means that all its dependencies have been processed.
							// Pick this task, removing it from the job queue.
							if (j->m_pendingJobs.is_equal(1u))
							{
								current_job = j;
								queue.erase(queue.begin() + i);
								break;
							}
						}
					}
				}
				worker_internal(queue, _index, current_job);
			}
		}

	public:
		// -----------------------------------------------------------------------------------------------
		scheduler() :
			m_threads(nullptr), m_scratch(nullptr), m_currentWorkerMaskDepth(0u)
		{
			memset((void*)m_currentWorkerMasks, ~0u, sizeof(uint32_t) * YATM_MAX_WORKER_MASK_STACK_DEPTH);

#if YATM_STD_THREAD
			m_hwConcurency = std::thread::hardware_concurrency();
#elif YATM_WIN64
			SYSTEM_INFO info;
			ZeroMemory(&info, sizeof(info));
			GetSystemInfo(&info);
			m_hwConcurency = info.dwNumberOfProcessors;
#elif YATM_LINUX
			m_hwConcurency = sysconf(_SC_NPROCESSORS_CONF);
#endif // YATM_STD_THREAD
		}

		// -----------------------------------------------------------------------------------------------
		virtual ~scheduler()
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

			// free the scratch allocator
			delete m_scratch;
			m_scratch = nullptr;

			for (uint32_t i = 0; i < m_queueCount; ++i)
			{
				m_jobQueue[i].clear();
			}
			delete[] m_jobQueue;
		}

		// -----------------------------------------------------------------------------------------------
		scheduler(const scheduler&) = delete;
		scheduler& operator=(const scheduler&) = delete;

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

				// Optinally copy custom worker ids (these will be used bitmasks when picking a worker for each job).
				m_threadData[i].m_id = (_desc.m_threadIds == nullptr) ? i : _desc.m_threadIds[i];
			}

			m_queueCount = m_numThreads;
			m_jobQueue = new std::vector<job*>[m_queueCount];

#if YATM_STD_THREAD
			YATM_TTY("yatm is using std::thread, configurable stack size is not allowed");
#endif // YATM_STD_THREAD

			m_stackSizeInBytes = align(_desc.m_stackSizeInBytes > 0 ? _desc.m_stackSizeInBytes : YATM_DEFAULT_STACK_SIZE, 16u);

			m_threads = new thread[m_numThreads];
			m_scratch = new scratch( align(_desc.m_jobScratchBufferInBytes, 16u), 16u);

			// reserve some space in the global job queue
			for (uint32_t i = 0; i < m_queueCount; ++i)
			{
				m_jobQueue[i].reserve(_desc.m_jobQueueReservation);
			}

			// reserve some space in the currently pending job queue
			m_pendingJobsToAdd.reserve(_desc.m_pendingJobQueueReservation);

			// enable the scheduler and let its workers run
			set_running(true);
			set_paused(false);

			// Create N worker threads and kick them off.
			// Each worker will process the next available job item from the global queue, resolve its dependencies and carry on until no jobs are left.
			for (uint32_t i = 0; i < m_numThreads; ++i)
			{
				auto func = [](void* data) -> void
				{
					worker_thread_data* d = reinterpret_cast<worker_thread_data*>(data);
					d->m_scheduler->worker_entry_point(d->m_id);
				};

				m_threads[i].create(i, m_stackSizeInBytes, func, &m_threadData[i]);
			}
		}

		// -----------------------------------------------------------------------------------------------
		// Resets the internal scratch allocator.
		// -----------------------------------------------------------------------------------------------
		void reset()
		{
			YATM_ASSERT(m_scratch != nullptr);
			m_scratch->reset();
		}

		// -----------------------------------------------------------------------------------------------
		// Push a new worker mask depth, subsequent job allocations will be set to run on the specified workers.
		// -----------------------------------------------------------------------------------------------
		void push_worker_mask(uint32_t _workerMask)
		{
			YATM_ASSERT(m_currentWorkerMaskDepth < YATM_MAX_WORKER_MASK_STACK_DEPTH);
			m_currentWorkerMasks[++m_currentWorkerMaskDepth] = _workerMask;
		}

		// -----------------------------------------------------------------------------------------------
		// Pop worker mask depth.
		// -----------------------------------------------------------------------------------------------
		void pop_worker_mask()
		{
			YATM_ASSERT(m_currentWorkerMaskDepth > 0);
			--m_currentWorkerMaskDepth;
		}

		// -----------------------------------------------------------------------------------------------
		// Create a job from the scheduler scratch allocator.
		// -----------------------------------------------------------------------------------------------
		template<typename Function>
		job* const create_job(const Function& _function, void* const _data, counter* _counter)
		{
			job* const j = allocate<job>();

			j->m_function = _function;
			j->m_data = _data;
			j->m_parent = nullptr;
			j->m_counter = _counter;
			j->m_workerMask = m_currentWorkerMasks[m_currentWorkerMaskDepth];

			// Initialise the job with 1 pending job (itself).
			// Adding dependencies increments the pending counter, resolving dependencies decrements it.
			j->m_pendingJobs.increment();

			// Register this newly created job; all jobs are automatically added when the scheduler kicks-off the tasks.
			scoped_lock<mutex> lock(&m_pendingJobsMutex);
			m_pendingJobsToAdd.push_back(j);

			return j;
		}

		// -----------------------------------------------------------------------------------------------
		// Create a group from the scheduler scratch allocator. A group is simply a job without any work to be done, used as a dependency in other
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
		// Allocate a temporary array using the scheduler scratch allocator.
		// -----------------------------------------------------------------------------------------------
		template<typename T>
		T* allocate(size_t _count, size_t _alignment = 16u)
		{
			uint8_t* mem = m_scratch->alloc(sizeof(T) * _count, _alignment);
			return new(mem) T[_count];
		}

		// -----------------------------------------------------------------------------------------------
		// Allocate a temporary object using the scheduler scratch allocator.
		// -----------------------------------------------------------------------------------------------
		template<typename T>
		T* allocate(size_t _alignment = 16u)
		{
			uint8_t* mem = m_scratch->alloc(sizeof(T), _alignment);

			T* obj = new(mem) T();
			return obj;
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
		void parallel_for(const Iterator& _begin, const Iterator& _end, const Function& _function)
		{
			const size_t n = std::distance(_begin, _end);
			if (n > 0)
			{
				// When there is only 1 job, don't pass it through the scheduler.
				if (n == 1)
				{
					_function(&(*(_begin)));
				}
				else
				{
					counter jobs_done;
					for (uint32_t i = 0; i < n; ++i)
					{
						job* j = create_job(_function, &(*(_begin + i)), &jobs_done);
					}

					kick();
					wait(&jobs_done);
				}
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

#if YATM_DEBUG
				verify_job_graph();
#endif // YATM_DEBUG

				for (auto& job : m_pendingJobsToAdd)
				{
					// Verify that the job and its data is allocated from scratch buffer.
					YATM_ASSERT(m_scratch->is_from(job));

					add_job(job);
				}
				m_pendingJobsToAdd.clear();
			}

			m_queueConditionVar.notify_all();
		}

		// -----------------------------------------------------------------------------------------------
		// Try to process the job on a compatible worker thread.
		// -----------------------------------------------------------------------------------------------
		void process_single_job()
		{
			yield();
			/*
			scoped_lock<mutex> lock(&m_queueMutex);
			std::vector<job*>& queue = get_random_queue();
			if (queue.size() > 0)
			{
				lock.unlock();

				// Find the worker able to process this job.
				for (uint32_t i = 0; i < m_numThreads; ++i)
				{
					const uint32_t id = m_threadData[i].m_id;
					if (worker_internal(queue, id))
					{
						return;
					}
				}
			}
			*/
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
		// Yield the current thread and allow others to execute.
		// -----------------------------------------------------------------------------------------------
		void yield()
		{
#if YATM_STD_THREAD
			std::this_thread::yield();
#elif YATM_WIN64
			SwitchToThread();
#elif YATM_USE_PTHREADS
			pthread_yield();
#endif // YATM_STD_THREAD
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
			m_queueConditionVar.notify_all();
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
			m_queueConditionVar.notify_all();
		}

		// -----------------------------------------------------------------------------------------------
		// Allow the current thread to sleep for specified duration in ms.
		// -----------------------------------------------------------------------------------------------
		void sleep(uint32_t ms)
		{
#if YATM_STD_THREAD
			std::this_thread::sleep_for(std::chrono::milliseconds(ms));
#elif YATM_WIN64
			Sleep(ms);
#elif YATM_LINUX
			usleep(ms * 1000);
#endif // YATM_STD_THREAD
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
		condition_var			m_queueConditionVar;
		mutex					m_queueMutex;
		mutex					m_pendingJobsMutex;
		size_t					m_stackSizeInBytes;
		uint32_t				m_hwConcurency;
		uint32_t				m_currentWorkerMasks[YATM_MAX_WORKER_MASK_STACK_DEPTH];
		uint32_t				m_currentWorkerMaskDepth;
		uint32_t				m_numThreads;
		uint32_t				m_queueCount;
		worker_thread_data*		m_threadData;
		bool					m_isRunning;
		bool					m_isPaused;		
		thread*					m_threads;
		std::vector<job*>*		m_jobQueue;
		std::vector<job*>		m_pendingJobsToAdd;

#if YATM_DEBUG
		// -----------------------------------------------------------------------------------------------
		// Verify the job graph.
		// -----------------------------------------------------------------------------------------------
		void verify_job_graph()
		{

		}
#endif // YATM_DEBUG

		// -----------------------------------------------------------------------------------------------
		// Get a random queue.
		// -----------------------------------------------------------------------------------------------
		std::vector<job*>& get_random_queue()
		{
			uint32_t const index = std::rand() % m_queueCount;
			return m_jobQueue[index];
		}

		// -----------------------------------------------------------------------------------------------
		// Adds a single job item to the scheduler. Assumes the caller ensures thread safety.
		// -----------------------------------------------------------------------------------------------
		void add_job(job* const _job)
		{
			YATM_ASSERT(_job != nullptr);

			if (_job->m_counter != nullptr)
			{
				_job->m_counter->increment();
			}

			get_random_queue().push_back(_job);
		}

		// -----------------------------------------------------------------------------------------------
		// Mark this job as finished by decrementing the pendingJobs counter and inform its parents recursively.
		// -----------------------------------------------------------------------------------------------
		void finish_job(job* const _job)
		{
			if (_job != nullptr)
			{
				const uint32_t p = _job->m_pendingJobs.decrement();
				// If this job has finished, inform its parent.
				if (p == 0)
				{
					finish_job(_job->m_parent);
				}
			}
		}

		// -----------------------------------------------------------------------------------------------
		// A scratch allocator to handle data and job allocations.
		// -----------------------------------------------------------------------------------------------
		class scratch
		{
		public:
			// -----------------------------------------------------------------------------------------------
			scratch(size_t _sizeInBytes, size_t _alignment)
				: m_sizeInBytes(_sizeInBytes), m_alignment(_alignment), m_begin(nullptr), m_end(nullptr), m_current(nullptr)

			{
				YATM_ASSERT(is_pow2(m_alignment));

				m_begin = (uint8_t*)aligned_alloc(m_sizeInBytes, m_alignment);
				YATM_ASSERT(m_begin != nullptr);

				m_end = m_begin + m_sizeInBytes;
				m_current = m_begin;
			}

			scratch(const scratch&) = delete;
			scratch& operator=(const scratch&) = delete;

			// -----------------------------------------------------------------------------------------------
			~scratch()
			{
				if (m_begin != nullptr)
				{
					aligned_free(m_begin);
				}
			}

			// -----------------------------------------------------------------------------------------------
			// Reset the scratch current pointer.
			// -----------------------------------------------------------------------------------------------
			void reset()
			{
				m_current = m_begin;
			}

			// -----------------------------------------------------------------------------------------------
			// Return the current (aligned) address of the scratch allocator and increment the pointer.
			// -----------------------------------------------------------------------------------------------
			uint8_t* alloc(size_t _size, size_t _align)
			{
				YATM_ASSERT(is_pow2(_align));

				scoped_lock<mutex> lock(&m_mutex);
				m_current = align_ptr(m_current, _align);

				YATM_ASSERT(m_current + _size < m_end);
				uint8_t* mem = m_current;
				m_current += _size;

#if YATM_DEBUG
				memset(mem, 0xbabababa, _size);
#endif // YATM_DEBUG

				return mem;
			}

			// -----------------------------------------------------------------------------------------------
			// Checks if the input pointer is within the scratch allocator's memory boundaries.
			// -----------------------------------------------------------------------------------------------
			bool is_from(void* _ptr)
			{
				const uint8_t* ptr = reinterpret_cast<const uint8_t*>(_ptr);
				return (ptr >= m_begin && ptr < m_end);
			}

		private:
			mutex		m_mutex;
			uint8_t*	m_begin;
			uint8_t*	m_end;
			uint8_t*	m_current;
			size_t		m_sizeInBytes;
			size_t		m_alignment;

			// -----------------------------------------------------------------------------------------------
			// Checks if the input is a power of two.
			// -----------------------------------------------------------------------------------------------
			bool is_pow2(size_t _n)
			{
				return (_n & (_n - 1)) == 0;
			}

		public:
			// -----------------------------------------------------------------------------------------------
			// A portable aligned allocation mechanism.
			//
			// Thanks to: https://gist.github.com/dblalock/255e76195676daa5cbc57b9b36d1c99a
			// -----------------------------------------------------------------------------------------------

			// -----------------------------------------------------------------------------------------------
			void* aligned_alloc(size_t _size, size_t _alignment)
			{
				YATM_ASSERT(_alignment < UINT8_MAX);

				// over-allocate using malloc and adjust pointer by the offset needed to align the memory to specified alignment
				const size_t request_size = _size + _alignment;
				uint8_t* buf = (uint8_t*)malloc(request_size);

				// figure out how much we should offset our allocation by
				const size_t remainder = ((size_t)buf) % _alignment;
				const size_t offset = _alignment - remainder;
				uint8_t* ret = buf + (uint8_t)offset;

				// store how many extra bytes we allocated in the byte just before the pointer we return
				*(uint8_t*)(ret - 1) = (uint8_t)offset;

				return ret;
			}

			// -----------------------------------------------------------------------------------------------
			void aligned_free(const void* const aligned_ptr)
			{
				// find the base allocation by extracting the stored aligned offset and free it
				uint32_t offset = *(((uint8_t*)aligned_ptr) - 1);
				free(((uint8_t*)aligned_ptr) - offset);
			}
		} *m_scratch;
	};
}
