import * as React from 'react';
import { Github as GithubIcon } from 'grommet-icons';
import { Heading, Accordion, AccordionPanel } from 'grommet';

import { isNotFoundError } from './client';
import useApp from './useApp';
import useRouter from './useRouter';
import { NavProtectionContext, buildNavProtectionContext } from './useNavProtection';

import { default as useErrorHandler, ErrorHandlerOption } from './useErrorHandler';
import Loading from './Loading';
import ExternalAnchor from './ExternalAnchor';
const FormationEditor = React.lazy(() => import('./FormationEditor'));
const ReleaseHistory = React.lazy(() => import('./ReleaseHistory'));
const EnvEditor = React.lazy(() => import('./EnvEditor'));
const MetadataEditor = React.lazy(() => import('./MetadataEditor'));

export interface Props {
	name: string;
}

/*
 * <AppComponent> is a container displaying information and executing
 * operations on an App given it's name.
 *
 * Notibly it provides
 *	- viewing/editing process scale
 *	- viewing/deploying release and scale history
 *	- viewing/editing environment variables
 *	- viewing/editing app metadata
 *
 * Example:
 *
 *	<AppComponent name="apps/70f9e916-5612-4634-b6f1-2df75c1dd5de" />
 *
 */
export default function AppComponent({ name }: Props) {
	const handleError = useErrorHandler(ErrorHandlerOption.PERSIST_AFTER_UNMOUNT);
	// Stream app
	const { app, loading: appLoading, error: appError } = useApp(name);
	const isAppDeleted = React.useMemo(
		() => {
			// if the app exists and we're getting a not found error, then it has been
			// deleted
			return app && appError && isNotFoundError(appError);
		},
		[appError] // eslint-disable-line react-hooks/exhaustive-deps
	);
	React.useEffect(
		() => {
			if (appError) {
				if (app && isNotFoundError(appError)) {
					handleError(new Error(`"${app.getDisplayName()}" has been deleted!`));
					history.push('/' + location.search);
				} else {
					handleError(new Error(`${app ? app.getDisplayName() : 'App(' + name + ')'}: ${appError.message}`));
				}
			}
		},
		[appError] // eslint-disable-line react-hooks/exhaustive-deps
	);
	React.useDebugValue(`App(${app ? name : 'null'})${appLoading ? ' (Loading)' : ''}`);

	const githubURL = React.useMemo<string | null>(
		() => {
			if (!app) {
				return null;
			}
			return app.getLabelsMap().get('github.url') || null;
		},
		[app]
	);

	const { history, location, urlParams } = useRouter();
	const activePanelIndices = urlParams.getAll('s').map((i: string) => parseInt(i, 10));
	const handlePanelSectionChange = (activePanelIndices: number[]) => {
		const nextUrlParams = new URLSearchParams(urlParams);
		nextUrlParams.delete('s');
		activePanelIndices.sort().forEach((i: number) => nextUrlParams.append('s', `${i}`));
		nextUrlParams.sort();
		history.replace(location.pathname + '?' + nextUrlParams.toString());
	};

	if (appLoading) {
		return <Loading />;
	}

	if (!app || isAppDeleted) {
		return null;
	}

	let panelIndex = 0;

	return (
		<>
			<Heading margin="xsmall">
				<>
					{app.getDisplayName()}
					{githubURL ? (
						<>
							&nbsp;
							<ExternalAnchor href={githubURL}>
								<GithubIcon />
							</ExternalAnchor>
						</>
					) : null}
				</>
			</Heading>
			<Accordion multiple animate={false} onActive={handlePanelSectionChange} activeIndex={activePanelIndices}>
				<AppComponentPanel label="Scale" index={panelIndex++}>
					<FormationEditor appName={app.getName()} />
				</AppComponentPanel>

				<AppComponentPanel label="Environment Variables" index={panelIndex++}>
					<EnvEditor appName={app.getName()} />
				</AppComponentPanel>

				<AppComponentPanel label="Metadata" index={panelIndex++}>
					<MetadataEditor appName={app.getName()} />
				</AppComponentPanel>

				<AppComponentPanel label="Release History" index={panelIndex++}>
					<ReleaseHistory appName={app.getName()} />
				</AppComponentPanel>
			</Accordion>
		</>
	);
}

interface AppComponentPanelProps {
	label: string;
	index: number;
	children: React.ReactNode;
}

const AppComponentPanel = ({ label, index, children }: AppComponentPanelProps) => {
	const navProtectionContext = React.useMemo(() => buildNavProtectionContext(`s=${index}`), [index]);
	return (
		<AccordionPanel label={label}>
			<React.Suspense fallback={<Loading />}>
				<NavProtectionContext.Provider value={navProtectionContext}>{children}</NavProtectionContext.Provider>
			</React.Suspense>
		</AccordionPanel>
	);
};
