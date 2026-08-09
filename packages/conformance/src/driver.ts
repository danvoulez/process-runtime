/**
 * The RuntimeDriver contract lives in @prt/driver-contract so that
 * neither the harness nor any reference runtime depends on each other.
 * Re-exported here for harness-internal convenience.
 */
export {
  type RuntimeDriver,
  type DriverFactory,
  type CreateProcessInput,
  type ProjectionView,
  asProjection,
  asReceipt,
} from "@prt/driver-contract";
