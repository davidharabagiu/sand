#include "mainexecuter.hpp"

namespace sand::utils
{
void MainExecuter::AddJob(const Job &job, Priority /*priority*/)
{
    job();
}

void MainExecuter::AddJob(Job &&job, Priority /*priority*/)
{
    job();
}
}  // namespace sand::utils
