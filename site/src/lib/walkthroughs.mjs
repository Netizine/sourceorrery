// The walkthroughs the docs embed: screens of the CLI's own screens, drawn by
// its design snapshots (`cargo test -p sourceorrery-cli ui::snapshot --
// --ignored`) in a dark and a light terminal, and copied into
// public/walkthrough/ by scripts/sync-walkthroughs.mjs. `state` is the
// snapshot's name; the page shows `title` and `caption` under each slide.
// Captions describe what is on the screen, so keep them in step with it.

/** @typedef {{ state: string, title: string, caption: string }} Slide */
/** @typedef {{ command: string, label: string, slides: Slide[] }} Walkthrough */

/** @type {Record<string, Walkthrough>} */
export const walkthroughs = {
	setup: {
		command: 'sourceorrery setup',
		label: 'Setting up a vault',
		slides: [
			{
				state: 'setup-first-vault',
				title: 'Start',
				caption:
					"With no vault yet, setup offers to create one. This machine's key goes into its credential store, so this machine opens the vault without asking.",
			},
			{
				state: 'setup-name',
				title: 'Name',
				caption:
					'Letters, digits, hyphens and underscores, up to 64. Commands, sourceorrery.toml and the SDKs refer to the vault by this name.',
			},
			{
				state: 'setup-view-check',
				title: 'View check',
				caption:
					'Optional: a password, and a code from an authenticator app on top, asked before anyone views the vault or reveals a value. run, check, init and the SDKs never ask it.',
			},
			{
				state: 'setup-password',
				title: 'Password',
				caption:
					'It must rate "good" or better, or setup generates one. What is typed is drawn as dots; the hint is shown when the check asks.',
			},
			{
				state: 'setup-authenticator',
				title: 'Authenticator',
				caption:
					'Scan the code, or type the key by hand, then enter a code from the app: the authenticator is kept only once a code matches.',
			},
			{
				state: 'setup-recovery-key',
				title: 'Recovery key',
				caption:
					'Shown once. It opens the vault on any other machine (WSL, a container, CI), so write it down and keep it apart from this one.',
			},
			{
				state: 'setup-storage',
				title: 'Storage',
				caption:
					'The vault file always. Tick HashiCorp Vault, AWS Secrets Manager or Azure Key Vault to keep secrets there too, through a connection the vault holds.',
			},
			{
				state: 'setup-connections',
				title: 'Connections',
				caption:
					"How each provider is reached: this machine's own sign-in, or credentials sealed in the vault. Test connection makes one metadata call.",
			},
			{
				state: 'setup-review',
				title: 'Review',
				caption: 'Nothing is written until Create vault, which makes the vault with all of this in one transaction.',
			},
			{
				state: 'setup-done',
				title: 'Done',
				caption: "The vault's file, its view check and its storage, and the commands to run next.",
			},
			{
				state: 'setup-start',
				title: 'Changing a vault',
				caption: 'Run setup again, or sourceorrery vault create NAME, to change a vault: its view check, its recovery key or its storage.',
			},
			{
				state: 'setup-unlock',
				title: 'Its view check first',
				caption:
					"Changing a vault asks its view check first (or its recovery key), so nobody at this machine can switch the check off from these screens.",
			},
		],
	},
	browser: {
		command: 'sourceorrery ui',
		label: 'Viewing a vault',
		slides: [
			{
				state: 'overview',
				title: 'Overview',
				caption:
					'The vault at a glance: secrets by status and by storage, what expires next, the audit chain, recent activity, the view check, connections and projects.',
			},
			{
				state: 'secrets',
				title: 'Secrets',
				caption:
					'Every secret with its status, where it is kept, its newest version and the projects that use it. No screen ever shows a value.',
			},
			{
				state: 'actions-60',
				title: 'Actions at a compact size',
				caption: 'F2 shows available actions and explains unavailable ones. Moving through the menu reads no additional vault or provider data.',
			},
			{
				state: 'filters-80',
				title: 'Filter cached metadata',
				caption: 'f offers status, expiry and tag categories with counts. The same query syntax remains available with /.',
			},
			{
				state: 'sort-60',
				title: 'Sort without losing the target',
				caption: 's sorts typed names or dates. Missing dates stay last and selection follows the same secret.',
			},
			{
				state: 'inspector-80',
				title: 'Complete cached details',
				caption: 'i wraps and scrolls full cached metadata, then returns to the same row. Enter still performs the explicit detail load when needed.',
			},
			{
				state: 'theme-preview-80',
				title: 'Reversible theme preview',
				caption: 't previews Dark, Light or Terminal for this session. Enter applies; Esc restores the prior choice. No-colour mode remains respected.',
			},
			{
				state: 'idle-warning-80',
				title: 'Idle-lock warning',
				caption: 'The last 30 seconds show a countdown. Display ticks do not read metadata or prolong the session; blocking provider work must finish before locking resumes.',
			},
			{
				state: 'detail',
				title: 'A secret',
				caption: "Its versions and metadata. e edits a version's metadata; n stores a new version from a hidden prompt.",
			},
			{
				state: 'add-secret',
				title: 'New secret',
				caption: 'a adds one: its name and where to keep it here, then its value at a hidden prompt with the screen suspended.',
			},
			{
				state: 'projects',
				title: 'Projects',
				caption: 'The folders whose manifests use this vault, checked on disk. x forgets one that is gone.',
			},
			{
				state: 'project-detail',
				title: 'A project',
				caption: 'Its folder, its manifest and the secrets it declares.',
			},
			{
				state: 'deleted',
				title: 'Deleted',
				caption: 'Soft-deleted secrets and when each is purged; u recovers one.',
			},
			{
				state: 'audit',
				title: 'Audit log',
				caption: 'Every read and change, newest first: who, what and the outcome. v verifies the chain again.',
			},
			{
				state: 'vaults',
				title: 'Vaults',
				caption: 'Every vault in the home directory. n creates one; c changes the selected one on the setup screens.',
			},
		],
	},
	init: {
		command: 'sourceorrery init',
		label: 'Setting up a project',
		slides: [
			{
				state: 'init-vault',
				title: 'Vault',
				caption: "Which vault the project's secrets come from.",
			},
			{
				state: 'init-project',
				title: 'Project',
				caption: "The project's name and where its manifest goes. The manifest names secrets; it never holds a value.",
			},
			{
				state: 'init-secrets',
				title: 'Secrets',
				caption: 'Tick the secrets the project uses, or All. The manifest declares them by name and run fetches their values.',
			},
			{
				state: 'init-add-new',
				title: 'New secrets',
				caption: 'Add the secrets the vault does not have yet, one at a time.',
			},
			{
				state: 'init-new-secret',
				title: 'A new secret',
				caption: 'Its value is typed twice, drawn as dots, and goes to the vault at Store.',
			},
			{
				state: 'init-review',
				title: 'Review',
				caption: 'What sourceorrery.toml will declare, each secret required or optional. Nothing is written before you confirm.',
			},
			{
				state: 'init-done',
				title: 'Done',
				caption: 'The manifest is written and the vault records the folder as a project. Next: check, then run.',
			},
		],
	},
};

/** The two terminals every slide is drawn in. */
export const looks = ['dark', 'light'];

/** Where a slide's page is served from. */
export function slideUrl(look, state) {
	return `/walkthrough/${look}/${state}.html`;
}
