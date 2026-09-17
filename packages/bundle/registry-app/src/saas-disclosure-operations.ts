/** Compose the process-global SaaS operation surface from Registry-owned routers and one narrow content adapter. */
import type { RegistryDisclosureContentProvider } from './disclosure-content-provider.ts'
import type { RegistryDisclosureOperations } from './operations.ts'
import type { RegistrySaasImportRouter } from './saas-import-queue.ts'
import type { RegistrySaasQuestionRouter } from './saas-question-mailbox.ts'

/** The Registry retains ownership of authorization, import and question routing.
 * A deployment may only supply the plaintext projection for an already authorized fixed prefix. */
export function createRegistrySaasDisclosureOperations(importRouter: RegistrySaasImportRouter,
  questionRouter: RegistrySaasQuestionRouter,
  contentProvider: RegistryDisclosureContentProvider | undefined): RegistryDisclosureOperations {
  return Object.freeze({
    ...(contentProvider === undefined ? {} : { readContent: contentProvider.readContent.bind(contentProvider) }),
    listImportTargets: importRouter.listImportTargets.bind(importRouter),
    importDisclosure: importRouter.importDisclosure.bind(importRouter),
    readImport: importRouter.readImport.bind(importRouter),
    listQuestions: questionRouter.listQuestions.bind(questionRouter),
    askDisclosure: questionRouter.askDisclosure.bind(questionRouter),
    readQuestion: questionRouter.readQuestion.bind(questionRouter),
    cancelQuestion: questionRouter.cancelQuestion.bind(questionRouter),
  })
}
