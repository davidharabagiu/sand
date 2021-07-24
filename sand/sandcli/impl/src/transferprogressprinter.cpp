#include "transferprogressprinter.hpp"

namespace sandcli
{
TransferProgressPrinter::TransferProgressPrinter(std::ostream &output_stream, int print_timeout_ms)
    : output_stream_ {output_stream}
    , print_timeout_ {print_timeout_ms}
    , latest_print_tp_ {}
    , bytes_transferred_on_latest_print_ {0}
{}

void TransferProgressPrinter::on_file_found()
{
    output_stream_ << "File found, starting transfer...\n";
}

void TransferProgressPrinter::on_transfer_progress_changed(
    size_t bytes_transferred, size_t total_bytes)
{
    auto now = Clock::now();

    if (latest_print_tp_.time_since_epoch().count() == 0)
    {
        // First progress update, cannot print now because transfer speed is TBD
        latest_print_tp_                   = now;
        bytes_transferred_on_latest_print_ = bytes_transferred;
        return;
    }

    if (bytes_transferred == total_bytes)
    {
        // Transfer completed, reset state
        latest_print_tp_                   = TimePoint {};
        bytes_transferred_on_latest_print_ = 0;
        return;
    }

    auto elapsed_time = now - latest_print_tp_;
    latest_print_tp_  = now;

    if (elapsed_time >= print_timeout_)
    {
        size_t progress_percentage = 100 * bytes_transferred / total_bytes;
        size_t transfer_speed_per_sec =
            (bytes_transferred - bytes_transferred_on_latest_print_) /
            size_t(std::chrono::duration_cast<std::chrono::seconds>(elapsed_time).count());

        std::string bytes_transferred_str = size_formatter_.format(bytes_transferred);
        std::string total_bytes_str       = size_formatter_.format(total_bytes);
        std::string transfer_speed_str    = size_formatter_.format(transfer_speed_per_sec);

        output_stream_ << progress_percentage << "% - " << bytes_transferred_str << " / "
                       << total_bytes_str << " - " << transfer_speed_str << "/s\n";
    }

    bytes_transferred_on_latest_print_ = bytes_transferred;
}
}  // namespace sandcli
