/** What a mod helper answers: the process exit code and what it writes to stdout. */
export interface HelperRun {
  code: 0 | 1;
  stdout: string;
}
