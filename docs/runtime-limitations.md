# Current runtime limitations

The runtime foundation is incremental. Legacy modules that still call existing helpers do not yet consume the shared transport budget or scope decisions. Those modules must be migrated before the centralized runtime can be considered authoritative for all target traffic.
