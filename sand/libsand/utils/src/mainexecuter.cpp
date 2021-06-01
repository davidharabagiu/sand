#include "mainexecuter.hpp"

#include <memory>

namespace sand::utils
{
CompletionToken MainExecuter::add_job(Job &&job, Priority /*priority*/)
{
    CompletionToken completion_token;
    job(completion_token);
    completion_token.complete();
    return completion_token;
}

void MainExecuter::process_all_jobs()
{
}
}  // namespace sand::utils
