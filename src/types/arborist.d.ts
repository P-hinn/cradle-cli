/**
 * Minimal type declarations for the slice of @npmcli/arborist we use.
 *
 * The package ships no types of its own, and the DefinitelyTyped package
 * (@types/npmcli__arborist) still describes v6 while we depend on v9 — stale
 * declarations would be worse than none. These were written against the real
 * runtime shape; see test/resolve/npm.test.ts for the behaviour they encode.
 */
declare module '@npmcli/arborist' {
  /** The subset of a package.json manifest we read off a tree node. */
  interface ArboristManifest {
    name?: string
    version?: string
    description?: string
    private?: boolean
    license?: unknown
    licenses?: unknown
    workspaces?: string[] | { packages?: string[] }
    [key: string]: unknown
  }

  type EdgeType = 'prod' | 'dev' | 'optional' | 'peer' | 'peerOptional' | 'workspace'

  interface ArboristEdge {
    readonly name: string
    readonly type: EdgeType
    /** Null when the dependency could not be resolved in this tree. */
    readonly to: ArboristNode | null
    readonly valid: boolean
  }

  interface ArboristNode {
    /** Path relative to the project root; the empty string for the root itself. */
    readonly location: string
    readonly name: string
    readonly version: string | undefined
    readonly package: ArboristManifest
    /** True for the `node_modules/<name>` symlinks npm creates for workspaces. */
    readonly isLink: boolean
    /** The real node a link points at. */
    readonly target: ArboristNode | null
    readonly isWorkspace: boolean
    /** Reachable only through development dependencies. */
    readonly dev: boolean
    /** Reachable only through optional dependencies. */
    readonly optional: boolean
    readonly devOptional: boolean
    readonly peer: boolean
    readonly extraneous: boolean
    readonly integrity: string | null
    readonly resolved: string | null
    readonly edgesOut: Map<string, ArboristEdge>
  }

  interface ArboristRoot extends ArboristNode {
    /** Every node in the tree, keyed by location. */
    readonly inventory: Map<string, ArboristNode>
  }

  export default class Arborist {
    constructor(options: { path: string })
    /** Builds the tree from the lockfile alone — no network, no node_modules. */
    loadVirtual(): Promise<ArboristRoot>
  }

  export type { ArboristEdge, ArboristManifest, ArboristNode, ArboristRoot, EdgeType }
}
