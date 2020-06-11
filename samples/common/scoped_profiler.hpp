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

#include <chrono>

namespace yatm
{
	// -----------------------------------------------------------------------------------------------
	class scoped_profiler
	{
	private:
		using clk = std::chrono::high_resolution_clock;
		using ms = std::chrono::milliseconds;
		using fsec = std::chrono::duration<float>;

	public:
		// -----------------------------------------------------------------------------------------------
		scoped_profiler()
		{
			m_start = clk::now();

			std::cout << "BEGIN" << std::endl;
		}

		// -----------------------------------------------------------------------------------------------
		~scoped_profiler()
		{
			auto end = clk::now();
			fsec fs = end - m_start;
			ms d = std::chrono::duration_cast<ms>(fs);

			std::cout << "END (Elapsed: " << d.count() << "ms)" << std::endl;
		}

	private:
		clk::time_point m_start;
	};
}
