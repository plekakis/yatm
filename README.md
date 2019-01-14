# yatm (yet another task manager)
A simple to use threaded task manager, supporting either std::thread or native thread libraries.
Customisable through a series of macros that change the behaviour of the scheduler:
* YATM_STD_THREAD
* YATM_WIN64
* YATM_NIX
* YATM_DEBUG
* YATM_TTY
* and more

# Installation
Simply include the yatm.hpp in your project. Before using it, certain #defines must be set, the most important ones being:
* Platform: currently either YATM_STD_THREAD or YATM_WIN64)
* YATM_DEBUG: 1 for builds that can assert, 0 otherwise 

## Example usage 1
This example shows how to initialise the scheduler and run 10 tasks asynchronously, waiting for their completion.
```cpp
yatm::scheduler sch;

// Initialise the scheduler
yatm::scheduler_desc desc;
desc.m_numThreads = sch.get_max_threads() - 1u;

sch.init(desc);

// Declare a counter that we'll use to wait for task completion
yatm::counter counter;

// Issue 10 tasks
for (uint32_t i=0; i<10; ++i)
{
  yatm::job* const test = sch.create_job
  (
    [](void* const _data)
    {
      // ...
      // lots of code here
      // ...      
    },
    nullptr,
    &counter
  );
}

// Signal the scheduler that tasks have been added and let the worker threads process them.
sch.kick();

// Wait for completion on all the 10 tasks added before.
sch.wait(&counter);
```

## Example usage 2
Extending the previous example, we pass in custom data. Job data is usually allocated using the built-in scratch allocator. The code is roughly the same as in the previous example, with the addition of the custom data array.
```cpp
yatm::scheduler sch;

// Initialise the scheduler
yatm::scheduler_desc desc;
desc.m_numThreads = sch.get_max_threads() - 1u;
desc.m_jobScratchBufferInBytes = 1024u;

sch.init(desc);

// Declare a counter that we'll use to wait for task completion
yatm::counter counter;

struct job_data
{
  uint32_t index;  
};

job_data* data = sch.allocate<job_data>(10u, 16u);

// Issue 10 tasks
for (uint32_t i=0; i<10; ++i)
{
  yatm::job* const test = sch.create_job
  (
    [](void* const _data)
    {
      const job_data& data = *((job_data*)_data);
      // ...
      // lots of code here, using data
      // ...      
    },
    data + i,
    &counter
  );
}

// Signal the scheduler that tasks have been added and let the worker threads process them.
sch.kick();

// Wait for completion on all the 10 tasks added before.
sch.wait(&counter);

// Reset the internal scratch allocator.
sch.reset();
```
## Example usage 3
This example illustrates parent-child relationships by setting up a dependency between 2 child tasks and 1 parent. The children finish first, then the parent.
```cpp
yatm::scheduler sch;

// Initialise the scheduler
yatm::scheduler_desc desc;
desc.m_numThreads = sch.get_max_threads() - 1u;

sch.init(desc);

// Create a parent task; this will be executed last, after all the children tasks have finished.
yatm::job* const parent = sch.create_job
(
  [](void* const _data)
  {
    // ...
    // code performing stuff that parent task should perform
    // ...
  },
  nullptr,
  nullptr
);

// Issue 10 tasks and make the parent depend on them
for (uint32_t i=0; i<10; ++i)
{
  yatm::job* const test = sch.create_job
  (
    [](void* const _data)
    {
      const job_data& data = *((job_data*)_data);
      // ...
      // lots of code here that the child will perform
      // ...      
    },
    nullptr,
    nullptr
  );
  
  // Tell the parent to depend on this child task
  sch.depend(parent, test);
}

// Signal the scheduler that tasks have been added and let the worker threads process them.
sch.kick();

// Wait for completion on all the 10 tasks added before. An alternative mechanism is used here instead of a counter,
// Simply waiting for the parent task to finish executing. A counter would also be valid.
sch.wait(parent);
```

**For a more complex example, please look into Source/yatm_sample.cpp**

# Bugs/Requests
Please use the GitHub issue tracker to submit bugs or request features.

# License
Copyright Pantelis Lekakis, 2019

Distributed under the terms of the MIT license, yatm is free and open source software.
