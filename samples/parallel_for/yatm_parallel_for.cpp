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
void sample_parallel_for(yatm::scheduler& sch)
{
	while (true)
	{
		sch.reset();
		{
			yatm::scoped_profiler profiler;

			// Setup some data for processing
			const uint32_t dataLength = 100u;
			uint32_t uints[dataLength];

			for (uint32_t i = 0; i < std::size(uints); i++)
			{
				uints[i] = i;
			}

			sch.push_worker_mask(~0u);

			// Launch them in parallel:
			// Creates as many tasks as the length of specified data, kicks them and blocks the caller thread until they are finished.
			sch.parallel_for((uint32_t*)uints, (uint32_t*)uints + dataLength, [](void* const param)
			{
				uint32_t idx = *(uint32_t*)param;

				// do some intensive work
				const auto result = yatm::work(idx);

				char t[64];
				sprintf_fn(t, "Result for data %u: %ld\n", idx, result);
				std::cout << t;
			});
			sch.pop_worker_mask();

			// An alternative way to specify functions, without lambdas.
			/*
			struct callback
			{
				void func(void* const param)
				{
					uint32_t idx = *(uint32_t*)param;

					// do some intensive work
					const auto result = work(idx);

					char t[64];
					sprintf_fn(t, "Result for data %u: %lld\n", idx, result);
					std::cout << t;
				}
			}owner;

			sch.parallel_for((uint32_t*)uints, (uint32_t*)uints + dataLength, yatm::bind(&callback::func, &owner));
			*/
		}
		sch.sleep(2000);
	}
}

// -----------------------------------------------------------------------------------------------
int main()
{
	yatm::scheduler sch;
	yatm::init(sch);
	sample_parallel_for(sch);
	return 0;
}
