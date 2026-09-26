import type { DependencyGraph, ResolvedComponent, ResolveNote } from '../../types/index.js'
import { CradleError } from '../errors.js'

/** Workspace members of this repository, in the order the graph lists them. */
export function workspaceNames(graph: DependencyGraph): string[] {
  return graph.components.filter((component) => component.workspace).map((c) => c.name)
}

/**
 * Narrow a repository-wide graph down to one workspace member: that member becomes
 * the product, and only what it actually depends on stays.
 *
 * Deriving this from the finished graph rather than resolving the member on its
 * own is the whole point. A monorepo has one lockfile, so a member scanned in
 * isolation would resolve differently from the same member scanned as part of the
 * repository — and then two cradle reports about the same code would disagree.
 * Slicing guarantees they cannot: same lockfile, same resolution, same versions,
 * different root.
 *
 * What changes is the route. `@acme/api › fastify › find-my-way` is the answer to
 * "can my team fix this"; the repository-wide report says `acme-monorepo ›
 * @acme/api › fastify › find-my-way`, which is the same fact with a step that
 * belongs to nobody in particular at the front.
 */
export function sliceWorkspace(graph: DependencyGraph, name: string): DependencyGraph {
  const member = graph.components.find(
    (component) => component.workspace && component.name === name,
  )
  if (member === undefined) {
    const available = workspaceNames(graph)
    throw new CradleError(
      available.length === 0
        ? `${graph.root.name} has no workspace packages, so --workspace has nothing to select`
        : `No workspace package named '${name}'`,
      available.length === 0
        ? 'Run cradle without --workspace to scan the whole project.'
        : `This repository has: ${available.join(', ')}.`,
    )
  }

  const reachable = new Set<string>()
  const queue = [member.bomRef]
  while (queue.length > 0) {
    const ref = queue.shift()
    if (ref === undefined || reachable.has(ref)) continue
    reachable.add(ref)
    queue.push(...(graph.edges.get(ref) ?? []))
  }
  // The member itself becomes metadata.component, not one of its own components.
  reachable.delete(member.bomRef)

  const direct = new Set(graph.edges.get(member.bomRef) ?? [])
  const components: ResolvedComponent[] = graph.components
    .filter((component) => reachable.has(component.bomRef))
    .map((component) => ({ ...component, direct: direct.has(component.bomRef) }))

  const edges = new Map<string, string[]>()
  edges.set(member.bomRef, [...(graph.edges.get(member.bomRef) ?? [])].sort())
  for (const component of components) {
    edges.set(
      component.bomRef,
      (graph.edges.get(component.bomRef) ?? []).filter(
        (target) => reachable.has(target) || target === member.bomRef,
      ),
    )
  }

  return {
    packageManager: graph.packageManager,
    projectDir: graph.projectDir,
    root: {
      bomRef: member.bomRef,
      name: member.name,
      version: member.version,
      purl: member.purl,
      licenses: member.licenses,
    },
    components,
    edges,
    includeDev: graph.includeDev,
    // Sibling members this one depends on. They stay components, because from
    // here they are dependencies like any other — just ones you can fix yourself.
    workspaces: components.filter((component) => component.workspace).map((c) => c.name),
    notes: notesFor(graph, components),
  }
}

/**
 * Keep the notes that are about this slice.
 *
 * A note that names a package outside the member's subtree is noise here. But a
 * note that names nothing in the repository at all — an `unresolved-dependency`
 * has only a bare name, and by definition no component — must be kept, because
 * dropping it would hide it from every report rather than moving it to the right
 * one.
 */
function notesFor(graph: DependencyGraph, components: readonly ResolvedComponent[]): ResolveNote[] {
  const inSlice = new Set<string>()
  for (const component of components) {
    inSlice.add(component.name)
    inSlice.add(`${component.name}@${component.version}`)
  }
  const anywhere = new Set<string>()
  for (const component of graph.components) {
    anywhere.add(component.name)
    anywhere.add(`${component.name}@${component.version}`)
  }

  return graph.notes.filter((note) => inSlice.has(note.subject) || !anywhere.has(note.subject))
}
