import * as React from 'react';
import * as jspb from 'google-protobuf';
import { Box, Button, Text } from 'grommet';

import useClient from './useClient';
import useAppScale from './useAppScale';
import useNavProtection from './useNavProtection';
import useErrorHandler from './useErrorHandler';
import Loading from './Loading';
import ProcessScale from './ProcessScale';
import ProcessesDiff from './ProcessesDiff';
import protoMapDiff, { applyProtoMapDiff, Diff } from './util/protoMapDiff';
import protoMapReplace from './util/protoMapReplace';
import { ScaleRequest, ScaleRequestState, CreateScaleRequest } from './generated/controller_pb';

function buildProcessesArray(m: jspb.Map<string, number>): [string, number][] {
	return Array.from(m.getEntryList()).sort(([ak, av]: [string, number], [bk, bv]: [string, number]) => {
		return ak.localeCompare(bk);
	});
}

interface Props {
	appName: string;
}

export default function FormationEditor({ appName }: Props) {
	const handleError = useErrorHandler();
	const client = useClient();
	const { scale, loading: isLoading, error: scaleError } = useAppScale(appName);
	const [initialProcesses, setInitialProcesses] = React.useState<jspb.Map<string, number>>(
		new jspb.Map<string, number>([])
	);
	const [processes, setProcesses] = React.useState<[string, number][]>([]);
	const [processesDiff, setProcessesDiff] = React.useState<Diff<string, number>>([]);
	const [hasChanges, setHasChanges] = React.useState(false);
	const [isConfirming, setIsConfirming] = React.useState(false);
	const [isCreating, setIsCreating] = React.useState(false);
	const [isScaleToZeroConfirmed, setIsScaleToZeroConfirmed] = React.useState(false);

	React.useEffect(
		() => {
			if (scaleError) {
				handleError(scaleError);
			}
		},
		[scaleError, handleError]
	);

	const [enableNavProtection, disableNavProtection] = useNavProtection();
	React.useEffect(
		() => {
			if (hasChanges) {
				enableNavProtection();
			} else {
				disableNavProtection();
			}
		},
		[hasChanges] // eslint-disable-line react-hooks/exhaustive-deps
	);

	React.useEffect(
		() => {
			if (!scale) return;

			// preserve changes
			let processesMap = scale.getNewProcessesMap();
			if (hasChanges) {
				processesMap = applyProtoMapDiff(processesMap, processesDiff);
			}

			setProcesses(buildProcessesArray(processesMap));
			setInitialProcesses(scale.getNewProcessesMap());
		},
		[scale] // eslint-disable-line react-hooks/exhaustive-deps
	);

	// set `processesDiff`, `processesFullDiff`, and `hasChanges` when
	// `processes` changes
	React.useEffect(
		() => {
			const diff = protoMapDiff(initialProcesses, new jspb.Map(processes));
			setProcessesDiff(diff);
			setHasChanges(diff.length > 0);
		},
		[processes] // eslint-disable-line react-hooks/exhaustive-deps
	);

	// used to render diff
	const nextScale = React.useMemo(
		() => {
			const s = new CreateScaleRequest();
			protoMapReplace(s.getProcessesMap(), new jspb.Map(processes));
			return s;
		},
		[processes]
	);

	function handleProcessChange(key: string, val: number) {
		setProcesses(processes.map(([k, v]: [string, number]) => {
			if (k === key) {
				return [k, val];
			}
			return [k, v];
		}) as [string, number][]);
	}

	function handleSubmit(e: React.SyntheticEvent) {
		e.preventDefault();
		setIsConfirming(true);
	}

	function handleConfirmSubmit(e: React.SyntheticEvent) {
		e.preventDefault();

		// build new formation object with new processes map
		if (!scale) return; // should never be null at this point

		setIsConfirming(false);
		setIsCreating(true);

		const req = new CreateScaleRequest();
		req.setParent(scale.getParent());
		protoMapReplace(req.getProcessesMap(), new jspb.Map(processes));
		protoMapReplace(req.getTagsMap(), scale.getNewTagsMap());
		client.createScale(req, (scaleReq: ScaleRequest, error: Error | null) => {
			setIsCreating(false);
			if (error) {
				handleError(error);
				return;
			}
			setProcesses(buildProcessesArray(scaleReq.getNewProcessesMap()));
		});
	}

	if (isLoading) {
		return <Loading />;
	}

	if (!scale) throw new Error('<FormationEditor> Error: Unexpected lack of scale!');

	const isPending = scale.getState() === ScaleRequestState.SCALE_PENDING;

	return (
		<Box as="form" onSubmit={isConfirming ? handleConfirmSubmit : handleSubmit} margin={{ bottom: 'xsmall' }}>
			{isConfirming || isCreating || isPending ? (
				<ProcessesDiff
					scale={scale}
					nextScale={nextScale}
					onConfirmScaleToZeroChange={(c) => setIsScaleToZeroConfirmed(c)}
				/>
			) : (
				<Box direction="row" gap="small" margin={{ bottom: 'xsmall' }}>
					{processes.length === 0 ? (
						<Text color="dark-2">&lt;No processes&gt;</Text>
					) : (
						processes.map(([key, val]: [string, number]) => (
							<Box align="center" key={key}>
								<ProcessScale
									value={val}
									label={key}
									editable
									onChange={(newVal) => {
										handleProcessChange(key, newVal);
									}}
								/>
							</Box>
						))
					)}
				</Box>
			)}
			<Box direction="row">
				{hasChanges && !isPending ? (
					isConfirming ? (
						<>
							<Button
								type="submit"
								primary={true}
								label="Confirm and Create Scale Request"
								disabled={!isScaleToZeroConfirmed}
							/>
							&nbsp;
							<Button
								type="button"
								label="Cancel"
								onClick={(e: React.SyntheticEvent) => {
									e.preventDefault();
									setIsConfirming(false);
								}}
							/>
						</>
					) : isCreating ? (
						<>
							<Button disabled primary={true} label="Creating Scale Request" />
						</>
					) : (
						<>
							<Button type="submit" primary={true} label="Create Scale Request" />
							&nbsp;
							<Button
								type="button"
								label="Reset"
								onClick={(e: React.SyntheticEvent) => {
									e.preventDefault();
									setProcesses(buildProcessesArray(initialProcesses));
								}}
							/>
						</>
					)
				) : (
					<Button disabled type="button" primary={true} label="Create Scale Request" />
				)}
			</Box>
		</Box>
	);
}
