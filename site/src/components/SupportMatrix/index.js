import React, { useEffect, useRef } from 'react';
import useBrokenLinks from '@docusaurus/useBrokenLinks';
import { SUPPORT_MATRIX, SUPPORT_MATRIX_CSS, enhanceSupportMatrix, renderSupportMatrix } from './supportmatrix.generated.js';

// The support matrix. supportmatrix.generated.js is generated from the Lean
// model (formal/slsa-tracks/matrix.json in the TestifySec monorepo) by
// `jade site support-matrix`; pushgate.dev renders the same file, so the two
// sites cannot disagree. Do not edit the generated file; edit the model or
// its overlay and regenerate.
//
// The markup is static HTML (it works with JavaScript off, and it is in the
// prerendered page). enhanceSupportMatrix turns it into a picker after
// hydration. The --sm-* properties map the renderer onto this site's tokens.
const SITE_TOKENS = `
.sm { --sm-ok: #1b7a4b; --sm-plan: #945800; --sm-no: var(--ifm-color-emphasis-700);
      --sm-line: var(--ifm-color-emphasis-300); --sm-bg: var(--ifm-background-surface-color);
      --sm-bg2: var(--ifm-color-emphasis-100); --sm-text: var(--ifm-font-color-base);
      --sm-muted: var(--ifm-color-emphasis-700); --sm-accent: var(--ifm-color-primary);
      --sm-radius: var(--ifm-global-radius); margin-bottom: var(--ifm-leading); }
[data-theme='dark'] .sm { --sm-ok: #4cc38a; --sm-plan: #f0b44c; --sm-bg: var(--ifm-background-color); }
`;

const HTML = renderSupportMatrix();

export default function SupportMatrix() {
	const ref = useRef(null);
	const brokenLinks = useBrokenLinks();
	// The anchors live in raw HTML, which the broken-link checker cannot see.
	brokenLinks.collectAnchor('sm-planned');
	SUPPORT_MATRIX.planned.forEach((p) => brokenLinks.collectAnchor(`sm-planned-${p.id}`));
	SUPPORT_MATRIX.envs.forEach((e) => brokenLinks.collectAnchor(`sm-env-${e.id}`));
	useEffect(() => {
		enhanceSupportMatrix(ref.current && ref.current.querySelector('[data-sm]'));
	}, []);
	return (
		<>
			<style dangerouslySetInnerHTML={{ __html: SUPPORT_MATRIX_CSS + SITE_TOKENS }} />
			<div ref={ref} dangerouslySetInnerHTML={{ __html: HTML }} />
		</>
	);
}
