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

#include <iostream>
#include <iterator>
#include <yatm.hpp>
#include "scoped_profiler.hpp"

#ifdef _MSC_VER
	#define sprintf_fn sprintf_s
#else
	#define sprintf_fn sprintf
#endif //_MSVC

namespace yatm
{
	// -----------------------------------------------------------------------------------------------
	static uint64_t work(uint32_t index)
	{
		uint64_t result = 0ull;
		for (uint32_t x = 0; x < 5000; ++x)
		{
			for (uint32_t y = 0; y < 5000; ++y)
			{
				result += (y ^ (x + 10)) * (y - 1);
				result = (result << (index % 16));
				result = result >> (index / 2 % 8);
			}
			result |= x;
		}

		return result;
	}

	// -----------------------------------------------------------------------------------------------
	static void init(scheduler& _scheduler, bool _singleThreaded = false)
	{
		// Initialise the scheduler
		scheduler_desc desc;
		memset(&desc, 0, sizeof(desc));

		if (_singleThreaded)
		{
			desc.m_numThreads = 1u;
		}
		else
		{
			desc.m_numThreads = _scheduler.get_max_threads() - 1u;
		}

		_scheduler.init(desc);
	}
}
