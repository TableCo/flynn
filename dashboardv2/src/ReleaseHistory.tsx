import * as React from 'react';
import * as timestamp_pb from 'google-protobuf/google/protobuf/timestamp_pb';
import styled from 'styled-components';

import { Checkmark as CheckmarkIcon } from 'grommet-icons';
import { CheckBox, Button, Box, BoxProps, Text } from 'grommet';
import ProcessScale from './ProcessScale';
import RightOverlay from './RightOverlay';

import { default as useRouter } from './useRouter';
import useApp from './useApp';
import useAppScale from './useAppScale';
import useAppScales from './useAppScales';
import useErrorHandler from './useErrorHandler';
import { listDeploymentsRequestFilterType, setNameFilters, setStreamUpdates, setStreamCreates } from './client';
import { ClientContext } from './withClient';
import {
	Release,
	ReleaseType,
	ReleaseTypeMap,
	Deployment,
	ExpandedDeployment,
	ScaleRequest,
	CreateScaleRequest,
	ScaleRequestState
} from './generated/controller_pb';
import Loading from './Loading';
import CreateDeployment from './CreateDeployment';
import CreateScaleRequestComponent from './CreateScaleRequest';
import ReleaseComponent from './Release';
import protoMapDiff, { Diff, DiffOp, DiffOption } from './util/protoMapDiff';
import protoMapReplace from './util/protoMapReplace';

interface MapHistoryProps<T> {
	deployments: ExpandedDeployment[];
	scales: ScaleRequest[];
	renderDate: (key: string, date: Date) => T;
	renderRelease: (key: string, releases: [Release, Release | null], index: number) => T;
	renderScale: (key: string, scaleRequest: ScaleRequest, index: number) => T;
}

function roundedDate(d: Date): Date {
	const out = new Date(d);
	out.setMilliseconds(0);
	out.setSeconds(0);
	out.setMinutes(0);
	out.setHours(0);
	return out;
}

const TODAY = roundedDate(new Date());

function isToday(d: Date): boolean {
	if (d.getFullYear() !== TODAY.getFullYear()) {
		return false;
	}
	if (d.getMonth() !== TODAY.getMonth()) {
		return false;
	}
	if (d.getDate() !== TODAY.getDate()) {
		return false;
	}
	return true;
}

function mapHistory<T>({ deployments, scales, renderRelease, renderScale, renderDate }: MapHistoryProps<T>): T[] {
	const res = [] as T[];
	const dlen = deployments.length;
	const slen = scales.length;
	let i = 0;
	let di = 0;
	let si = 0;
	let date: Date | null = null;
	while (di < dlen || si < slen) {
		let d = deployments[di];
		let r = d ? d.getNewRelease() || null : null;
		let pr = d ? d.getOldRelease() || null : null;
		const dt = d ? (d.getCreateTime() as timestamp_pb.Timestamp).toDate() : null;
		const s = scales[si];
		const st = s ? (s.getCreateTime() as timestamp_pb.Timestamp).toDate() : null;
		let prevDate = date;
		let el: T;
		if ((dt && st && dt > st) || (dt && !st)) {
			date = roundedDate(dt);
			el = renderRelease(d.getName(), [r as Release, pr], i);
			di++;
			i++;
		} else if (st) {
			date = roundedDate(st);
			el = renderScale(s.getName(), s, i);
			si++;
			i++;
		} else {
			break;
		}

		if (prevDate === null || date < prevDate) {
			res.push(renderDate(date.toDateString(), date));
		}

		res.push(el);
	}
	return res;
}

interface SelectableBoxProps {
	selected: boolean;
	highlighted: boolean;
}

const selectedBoxCSS = `
	background-color: var(--active);
`;

const highlightedBoxCSS = `
	border-left: 4px solid var(--brand);
`;

const nonHighlightedBoxCSS = `
	border-left: 4px solid transparent;
`;

const SelectableBox = styled(Box)`
	&:hover {
		background-color: var(--active);
	}
	padding-left: 2px;

	${(props: SelectableBoxProps) => (props.selected ? selectedBoxCSS : '')};
	${(props: SelectableBoxProps) => (props.highlighted ? highlightedBoxCSS : nonHighlightedBoxCSS)};
`;

const StickyBox = styled(Box)`
	position: sticky;
	top: -1px;
`;

interface ReleaseHistoryDateHeaderProps extends BoxProps {
	date: Date;
}

function ReleaseHistoryDateHeader({ date, ...boxProps }: ReleaseHistoryDateHeaderProps) {
	return (
		<StickyBox {...boxProps}>
			<Box round background="background" alignSelf="center" pad="small">
				{isToday(date) ? 'Today' : date.toDateString()}
			</Box>
		</StickyBox>
	);
}

interface ReleaseHistoryReleaseProps extends BoxProps {
	selected: boolean;
	isCurrent: boolean;
	release: Release;
	prevRelease: Release | null;
	onChange: (isSelected: boolean) => void;
}

function ReleaseHistoryRelease({
	release: r,
	prevRelease: p,
	selected,
	isCurrent,
	onChange,
	...boxProps
}: ReleaseHistoryReleaseProps) {
	return (
		<SelectableBox selected={selected} highlighted={isCurrent} {...boxProps}>
			<label>
				<CheckBox
					checked={selected}
					indeterminate={!selected && isCurrent}
					onChange={(e: React.ChangeEvent<HTMLInputElement>) => onChange(e.target.checked)}
				/>
				<ReleaseComponent release={r} prevRelease={p} />
			</label>
		</SelectableBox>
	);
}

interface ReleaseHistoryScaleProps extends BoxProps {
	selected: boolean;
	isCurrent: boolean;
	scaleRequest: ScaleRequest;
	onChange: (isSelected: boolean) => void;
}

function ReleaseHistoryScale({
	scaleRequest: s,
	selected,
	isCurrent,
	onChange,
	...boxProps
}: ReleaseHistoryScaleProps) {
	const releaseID = s.getParent().split('/')[3];
	const diff = protoMapDiff(s.getOldProcessesMap(), s.getNewProcessesMap(), DiffOption.INCLUDE_UNCHANGED);
	return (
		<SelectableBox selected={selected} highlighted={isCurrent} {...boxProps}>
			<label>
				<CheckBox
					checked={selected}
					indeterminate={!selected && isCurrent}
					onChange={(e: React.ChangeEvent<HTMLInputElement>) => onChange(e.target.checked)}
				/>
				<div>
					<div>Release {releaseID}</div>
					<div>
						{(() => {
							switch (s.getState()) {
								case ScaleRequestState.SCALE_PENDING:
									return 'PENDING';
								case ScaleRequestState.SCALE_CANCELLED:
									return 'CANCELED';
								case ScaleRequestState.SCALE_COMPLETE:
									return 'COMPLETE';
								default:
									return 'UNKNOWN';
							}
						})()}
					</div>
					<Box direction="row">
						{diff.length === 0 ? <Text color="dark-2">&lt;No processes&gt;</Text> : null}
						{diff.reduce(
							(m: React.ReactNodeArray, op: DiffOp<string, number>) => {
								if (op.op === 'remove') {
									return m;
								}
								let val = op.value;
								let prevVal = s.getOldProcessesMap().get(op.key);
								if (op.op === 'keep') {
									val = prevVal;
								}
								m.push(
									<ProcessScale
										key={op.key}
										direction="row"
										margin="small"
										size="small"
										value={val as number}
										originalValue={prevVal}
										showDelta
										label={op.key}
									/>
								);
								return m;
							},
							[] as React.ReactNodeArray
						)}
					</Box>
				</div>
			</label>
		</SelectableBox>
	);
}

export interface Props {
	appName: string;
}

enum SelectedResourceType {
	Release = 1,
	ScaleRequest
}

export default function ReleaseHistory({ appName }: Props) {
	const handleError = useErrorHandler();
	const [isDeploying, setIsDeploying] = React.useState(false);

	const { app, loading: appLoading, error: appError } = useApp(appName);
	React.useEffect(
		() => {
			if (appError) {
				handleError(appError);
			}
		},
		[appError, handleError]
	);

	const currentReleaseName = React.useMemo(
		() => {
			if (!app) return '';
			return app.getRelease();
		},
		[app]
	);

	const [selectedItemName, setSelectedItemName] = React.useState<string>('');
	React.useEffect(
		() => {
			if (!currentReleaseName) return;
			setSelectedItemName(currentReleaseName);
		},
		[currentReleaseName]
	);

	const { urlParams } = useRouter();
	const releasesListFilters = [urlParams.getAll('rhf'), ['code', 'env', 'scale']].find((i) => i.length > 0) as string[];

	const rhf = releasesListFilters;
	const isCodeReleaseEnabled = React.useMemo(
		() => {
			return rhf.length === 0 || rhf.indexOf('code') !== -1;
		},
		[rhf]
	);
	const isConfigReleaseEnabled = React.useMemo(
		() => {
			return rhf.indexOf('env') !== -1;
		},
		[rhf]
	);
	const isScaleEnabled = React.useMemo(
		() => {
			return rhf.indexOf('scale') !== -1;
		},
		[rhf]
	);

	const client = React.useContext(ClientContext);

	// Stream deployments
	const [deployments, setDeployments] = React.useState<ExpandedDeployment[]>([]);
	const [deploymentsLoading, setDeploymentsLoading] = React.useState(false);
	React.useEffect(
		() => {
			if (!isCodeReleaseEnabled && !isConfigReleaseEnabled) {
				setDeploymentsLoading(false);
				return;
			}

			let filterType = ReleaseType.ANY as ReleaseTypeMap[keyof ReleaseTypeMap];
			if (isCodeReleaseEnabled && !isConfigReleaseEnabled) {
				filterType = ReleaseType.CODE;
			} else if (isConfigReleaseEnabled && !isCodeReleaseEnabled) {
				filterType = ReleaseType.CONFIG;
			}

			const cancel = client.streamDeployments(
				(deployments: ExpandedDeployment[], error: Error | null) => {
					if (error) {
						handleError(error);
						return;
					}

					setDeployments(deployments);
					setDeploymentsLoading(false);
				},
				setNameFilters(appName),
				listDeploymentsRequestFilterType(filterType),
				setStreamUpdates(),
				setStreamCreates()
			);
			return cancel;
		},
		[appName, client, handleError, isCodeReleaseEnabled, isConfigReleaseEnabled]
	);

	// Get scale requests
	const { scales, loading: scalesLoading, error: scalesError } = useAppScales(appName, isScaleEnabled);
	React.useEffect(
		() => {
			if (scalesError) {
				handleError(scalesError);
			}
		},
		[handleError, scalesError]
	);

	// Get current formation
	const { scale: currentScale, loading: currentScaleLoading, error: currentScaleError } = useAppScale(appName);
	React.useEffect(
		() => {
			if (currentScaleError) {
				handleError(currentScaleError);
			}
		},
		[currentScaleError, handleError]
	);

	const [selectedResourceType, setSelectedResourceType] = React.useState<SelectedResourceType>(
		SelectedResourceType.Release
	);
	const [selectedScaleRequestDiff, setSelectedScaleRequestDiff] = React.useState<Diff<string, number>>([]);

	// keep updated scale request diff
	React.useEffect(
		() => {
			if (isDeploying) return;

			if (selectedResourceType === SelectedResourceType.ScaleRequest) {
				const sr = scales.find((sr) => sr.getName() === selectedItemName);
				if (sr) {
					const diff = protoMapDiff((currentScale as ScaleRequest).getNewProcessesMap(), sr.getNewProcessesMap());
					setSelectedScaleRequestDiff(diff);
					return;
				}
			}
			setSelectedScaleRequestDiff([]);
		},
		[currentScale, isDeploying, scales, selectedItemName, selectedResourceType]
	);

	const [nextScale, setNextScale] = React.useState<CreateScaleRequest | null>(null);
	const [nextReleaseName, setNextReleaseName] = React.useState('');
	const submitHandler = (e: React.SyntheticEvent) => {
		e.preventDefault();

		if (selectedItemName === '') {
			return;
		}

		if (selectedResourceType === SelectedResourceType.ScaleRequest) {
			// It's a scale request we're deploying
			const sr = scales.find((sr) => sr.getName() === selectedItemName);
			const nextScale = new CreateScaleRequest();
			if (!sr) {
				return;
			}
			nextScale.setParent(sr.getParent());
			protoMapReplace(nextScale.getProcessesMap(), sr.getNewProcessesMap());
			protoMapReplace(nextScale.getTagsMap(), sr.getNewTagsMap());
			setNextScale(nextScale);
			if (selectedItemName.startsWith(currentReleaseName)) {
				// We're scaling the current release
				setNextReleaseName(currentReleaseName);
			} else {
				// We're deploying and scaling a release
				setNextReleaseName(sr.getParent());
			}
			setIsDeploying(true);
		} else {
			// It's a release we're deploying
			setNextReleaseName(selectedItemName);
			setNextScale(null);
			setIsDeploying(true);
		}
	};

	const handleDeployCancel = () => {
		setIsDeploying(false);
		setNextReleaseName('');
		setNextScale(null);
	};

	const handleDeployComplete = (item: Deployment | ScaleRequest) => {
		setIsDeploying(false);
		setNextReleaseName('');
		setNextScale(null);
	};

	if (deploymentsLoading || scalesLoading || currentScaleLoading || appLoading) {
		return <Loading />;
	}

	return (
		<>
			{isDeploying ? (
				<RightOverlay onClose={handleDeployCancel}>
					{selectedResourceType === SelectedResourceType.ScaleRequest &&
					nextReleaseName &&
					nextReleaseName === currentReleaseName &&
					nextScale ? (
						<CreateScaleRequestComponent
							appName={appName}
							nextScale={nextScale}
							onCancel={handleDeployCancel}
							onCreate={handleDeployComplete}
							handleError={handleError}
						/>
					) : (
						<CreateDeployment
							appName={appName}
							releaseName={nextReleaseName}
							newScale={nextScale || undefined}
							onCancel={handleDeployCancel}
							onCreate={handleDeployComplete}
							handleError={handleError}
						/>
					)}
				</RightOverlay>
			) : null}

			<form onSubmit={submitHandler}>
				<Box tag="ul">
					{mapHistory({
						deployments,
						scales: isScaleEnabled ? scales : [],
						renderDate: (key, date) => <ReleaseHistoryDateHeader key={key} date={date} tag="li" margin="xsmall" />,
						renderRelease: (key, [r, p]) => (
							<ReleaseHistoryRelease
								key={key}
								tag="li"
								margin={{ bottom: 'small' }}
								release={r}
								prevRelease={p}
								selected={selectedItemName === r.getName()}
								isCurrent={currentReleaseName === r.getName()}
								onChange={(isSelected) => {
									if (isSelected) {
										setSelectedItemName(r.getName());
										setSelectedResourceType(SelectedResourceType.Release);
									} else {
										setSelectedItemName(currentReleaseName);
										setSelectedResourceType(SelectedResourceType.Release);
									}
								}}
							/>
						),
						renderScale: (key, s) => (
							<ReleaseHistoryScale
								key={key}
								tag="li"
								margin={{ bottom: 'small' }}
								scaleRequest={s}
								selected={selectedItemName === s.getName()}
								isCurrent={currentScale ? currentScale.getName() === s.getName() : false}
								onChange={(isSelected) => {
									if (isSelected) {
										setSelectedItemName(s.getName());
										setSelectedResourceType(SelectedResourceType.ScaleRequest);
									} else {
										setSelectedItemName(currentReleaseName);
										setSelectedResourceType(SelectedResourceType.Release);
									}
								}}
							/>
						)
					})}
				</Box>

				{selectedResourceType === SelectedResourceType.ScaleRequest ? (
					selectedItemName.startsWith(currentReleaseName) ? (
						<Button
							type="submit"
							disabled={(selectedScaleRequestDiff as Diff<string, number>).length === 0}
							primary
							icon={<CheckmarkIcon />}
							label="Scale Release"
						/>
					) : (
						<Button type="submit" primary icon={<CheckmarkIcon />} label="Deploy Release / Scale" />
					)
				) : (
					<Button
						type="submit"
						disabled={selectedItemName === currentReleaseName}
						primary
						icon={<CheckmarkIcon />}
						label="Deploy Release"
					/>
				)}
			</form>
		</>
	);
}
