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
#define YATM_STD_THREAD (0u)

#include "../common/sample.hpp"

// -----------------------------------------------------------------------------------------------
void sample_job_dependencies(yatm::scheduler& sch)
{
	static uint32_t c_numChildTasks = 30;	// group child tasks.
	static uint32_t c_numIterations = ~0u;	// -1 for infinite iterations

	// Run for N iterations
	uint32_t iter = 0u;
	float averageMs = 0.0f;
	while ((iter++ < c_numIterations) || (c_numIterations == ~0u))
	{
		sch.reset();

		{
			yatm::scoped_profiler profiler;

			yatm::counter counter;

			// Prepare the job graph
			// This looks like this:
			/*
			[parent]
			/	     \
			/		  \
			[group0]	      [group1]
			/						\
			/						 \
			[group0_job]				  [group1_job]
			|							|
			|							|
			|---> child_0				|---> child_0
			| ....						| ...
			|---> child_n				|---> child_n

			Expected result is the children of each [groupN_job] task to be executed first. When all of the dependencies of each [groupN_job] are resolved,
			[groupN_job] will be executed. Once that happens, [groupN] is executed (being a simple group without a job function, it does nothing, simply used for grouping).
			Once both [group0] and [group1] are finished, [parent] executes and the tasks are complete.

			After [parent] is finished, sch.wait(parent) will unblock and main thread execution will continue.
			An alternative way to wait for the tasks to finish is by using the yatm::counter object. This is atomically incremented when jobs that reference it are added to
			the scheduler and decremented when jobs are finished. When the counter reached 0, it's assumed to be finished and sch.wait(&counter) will unblock the main thread.

			*/
			// Parent task depends on everything else below. This will be executed last.
			yatm::job* const parent = sch.create_job
			(
				[](void* const data)
				{
					std::cout << "Parent, this should execute after all the groups have finished.\n";
				}
				,
				nullptr,
				&counter
				);

			// allocate data for the child tasks; they simply hold the loop index, but more complex structures can be used.
			uint32_t* const data = sch.allocate<uint32_t>(c_numChildTasks, 16u);

			// Make a few groups to put the children jobs under. Group0 will depend on children [0, N/2-1] and group1 will depend on children [N/2, N]
			// Group0_job and group1_job will execute once their respective children have finished executing.
			yatm::job* const group0 = sch.create_group(parent);
			yatm::job* const group0_job = sch.create_job([](void* const data) { std::cout << "Group 0 job, executing after all child 0 are finished.\n"; }, nullptr, &counter);
			sch.depend(group0, group0_job);

			yatm::job* const group1 = sch.create_group(parent);
			yatm::job* const group1_job = sch.create_job([](void* const data) { std::cout << "Group 1 job, executing after all child 1 are finished.\n"; }, nullptr, &counter);
			sch.depend(group1, group1_job);

			// Create child tasks
			for (uint32_t i = 0; i < c_numChildTasks; ++i)
			{
				data[i] = i;
				yatm::job* const child = sch.create_job
				(
					[](void* const data)
					{
						uint32_t idx = *(uint32_t*)data;

						// do some intensive work
						uint64_t result = yatm::work(idx);

						const uint32_t group = idx < c_numChildTasks / 2 ? 0 : 1;
						char str[512];
						sprintf_fn(str, "Child %u (group %u). Children of groups should execute first, result: %ld.\n", idx, group, result);

						std::cout << str;
					},
					&data[i],
					&counter
					);

				if (i < c_numChildTasks / 2)
				{
					sch.depend(group0_job, child);
				}
				else
				{
					sch.depend(group1_job, child);
				}
			}

			// Add the created tasks and signal the workers to begin processing them
			sch.kick();
			// Wait for finished tasks. Here we wait on the parent, as this will guarantee that all of the tasks will be complete.
			sch.wait(parent);

			// Or:
			// sch.wait(&counter);
			//
			// The counter can also be only added on the parent (instead of all the tasks, as done above).
			// Since the parent depends on all the other tasks, having the counter only on that single job is enough.
		}
		// Pause for a bit, resume after 1000ms
		sch.set_paused(true);
		sch.sleep(1000);
		sch.set_paused(false);
	}
	sch.set_running(false);
	sch.sleep(2000);
}

// -----------------------------------------------------------------------------------------------
int main()
{
	yatm::scheduler sch;
	yatm::init(sch);
	sample_job_dependencies(sch);
	return 0;
}
