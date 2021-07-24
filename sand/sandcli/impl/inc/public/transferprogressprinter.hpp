#ifndef SANDCLI_TRANSFERPROGRESSPRINTER_HPP_
#define SANDCLI_TRANSFERPROGRESSPRINTER_HPP_

#include <chrono>
#include <ostream>

#include "datasizeformatter.hpp"
#include "sandnodelistener.hpp"

namespace sandcli
{
class TransferProgressPrinter : public sand::SANDNodeListener
{
public:
    TransferProgressPrinter(std::ostream &output_stream, int print_timeout_ms);

    void on_file_found() override;
    void on_transfer_progress_changed(size_t bytes_transferred, size_t total_bytes) override;

private:
    using Clock     = std::chrono::steady_clock;
    using TimePoint = std::chrono::time_point<Clock>;

    std::ostream &            output_stream_;
    std::chrono::milliseconds print_timeout_;
    TimePoint                 latest_print_tp_;
    size_t                    bytes_transferred_on_latest_print_;
    DataSizeFormatter         size_formatter_;
};
}  // namespace sandcli

#endif  // SANDCLI_TRANSFERPROGRESSPRINTER_HPP_
