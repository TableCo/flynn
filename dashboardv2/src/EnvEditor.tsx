import * as React from 'react';
import Loading from './Loading';
import CreateDeployment from './CreateDeployment';
import KeyValueEditor, { KeyValueData } from './KeyValueEditor';
import protoMapDiff, { applyProtoMapDiff } from './util/protoMapDiff';
import protoMapReplace from './util/protoMapReplace';
import { handleError } from './withErrorHandler';
import { Release } from './generated/controller_pb';
import RightOverlay from './RightOverlay';
import { isNotFoundError } from './client';
import useAppRelease from './useAppRelease';

interface Props {
	appName: string;
}

export default function EnvEditor({ appName }: Props) {
	// Stream app release
	const { release: currentRelease, loading: releaseIsLoading, error: releaseError } = useAppRelease(appName);
	// handle app not having a release (useMemo so it uses the same value over
	// multiple renders so as not to over-trigger hooks depending on `release`)
	const initialRelease = React.useMemo(() => new Release(), []);
	const release = currentRelease || initialRelease;

	const [data, setData] = React.useState<KeyValueData | null>(null);
	const [isDeploying, setIsDeploying] = React.useState(false);

	// newRelease is used to create a deployment
	const newRelease = React.useMemo(
		() => {
			if (!release) return new Release();
			const diff = data ? protoMapDiff(release.getEnvMap(), data.entries()) : [];
			const newRelease = new Release();
			newRelease.setArtifactsList(release.getArtifactsList());
			protoMapReplace(newRelease.getLabelsMap(), release.getLabelsMap());
			protoMapReplace(newRelease.getProcessesMap(), release.getProcessesMap());
			protoMapReplace(newRelease.getEnvMap(), applyProtoMapDiff(release.getEnvMap(), diff));
			return newRelease;
		},
		[release, data]
	);

	React.useEffect(
		() => {
			// handle any non-404 errors (not all apps have a release yet)
			if (releaseError && !isNotFoundError(releaseError)) {
				return handleError(releaseError);
			}

			// maintain any non-conflicting changes made when new release arrives
			if (!release || !release.getName() || !data) return;
			const nextData = data.rebase(release.getEnvMap());
			setData(nextData);
		},
		[release, releaseError] // eslint-disable-line react-hooks/exhaustive-deps
	);

	const handleSubmit = (data: KeyValueData) => {
		setIsDeploying(true);
		setData(data);
	};

	const handleDeployDismiss = () => {
		setIsDeploying(false);
	};

	const handleDeployComplete = () => {
		setIsDeploying(false);
		setData(null);
	};

	if (releaseIsLoading) {
		return <Loading />;
	}

	if (!release) throw new Error('<EnvEditor> Error: Unexpected lack of release');

	return (
		<>
			{isDeploying ? (
				<RightOverlay onClose={handleDeployDismiss}>
					<CreateDeployment
						appName={appName}
						newRelease={newRelease || new Release()}
						onCancel={handleDeployDismiss}
						onCreate={handleDeployComplete}
					/>
				</RightOverlay>
			) : null}
			<KeyValueEditor
				data={data || new KeyValueData(release.getEnvMap())}
				keyPlaceholder="ENV key"
				valuePlaceholder="ENV value"
				onChange={(data) => {
					setData(data);
				}}
				onSubmit={handleSubmit}
				conflictsMessage="Some edited keys have been updated in the latest release"
			/>
		</>
	);
}
