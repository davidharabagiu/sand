#include "mainexecuter.hpp"

#include <memory>

namespace sand::utils
{
void MainExecuter::add_job(Job &&job, Priority /*priority*/)
{
    job();
}
}  // namespace sand::utils
