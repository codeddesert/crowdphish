import time

from django.core.management.base import BaseCommand

from phishing.resolve import claim_batch, execute_resolve


class Command(BaseCommand):
    help = "Fetch RFC822 metadata for pending Gmail reports."

    def add_arguments(self, parser):
        parser.add_argument("--loop", action="store_true", help="Keep polling for pending reports.")
        parser.add_argument("--limit", type=int, default=25)

    def handle(self, *args, **options):
        limit = max(1, options["limit"])
        if options["loop"]:
            while True:
                processed = self._once(limit)
                time.sleep(2 if processed else 5)
            return
        self._once(limit)

    def _once(self, limit):
        claimed = claim_batch(limit)
        for report_id in claimed:
            execute_resolve(report_id)
            self.stdout.write(f"resolved {report_id}")
        return len(claimed)
