# Vendored copy of the upstream error-reporting client, kept in-tree so the
# build does not depend on the gem being resolvable.
module Acme
  module Vendor
    class ReportingClient
      INGEST_URL = 'https://sentry.io/api/1/store/'

      def report(event)
        post(INGEST_URL, event.to_json)
      end
    end
  end
end
