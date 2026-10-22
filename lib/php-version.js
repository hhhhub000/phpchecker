// PHP バージョン文字列の抽出と PHP2Shell (CVE-2026-109618 / CVE-2026-109619) 修正版との照合。

export const CVE_IDS = ['CVE-2026-109618', 'CVE-2026-109619'];

// ブランチごとの修正版パッチ番号（8.1 以前は公式修正なし）
export const FIXED_VERSIONS = { '8.2': 35, '8.3': 36, '8.4': 27, '8.5': 12 };

const DISTRO_RE = /ubuntu|deb|\.el\d|bpo|sury|\+|amzn|fc\d/i;

/** "PHP/8.1.2-1ubuntu2.14" や "PHP Version 8.3.30" からバージョンを取り出す */
export function extractPhpVersions(text) {
  if (!text) return [];
  const found = [];
  const re = /PHP(?:\/|\s+Version\s+|\s+)(\d+)\.(\d+)\.(\d+)([-+~][A-Za-z0-9.+~:-]*)?/gi;
  for (const m of String(text).matchAll(re)) {
    found.push({
      raw: `${m[1]}.${m[2]}.${m[3]}${m[4] || ''}`,
      major: Number(m[1]),
      minor: Number(m[2]),
      patch: Number(m[3]),
      suffix: m[4] || '',
    });
  }
  return found;
}

export function isDistroBuild(version) {
  return DISTRO_RE.test(version.suffix || '');
}

/** 修正版との比較結果を { status, message } で返す */
export function assessPhpVersion(version) {
  const branch = `${version.major}.${version.minor}`;
  const distro = isDistroBuild(version);
  const distroNote = distro
    ? '（ディストリビューションのビルド表記あり。バックポートで修正済みの可能性があるため、ディストリのセキュリティ情報のビルド番号と照合してください）'
    : '';

  if (version.major < 8 || (version.major === 8 && version.minor <= 1)) {
    return {
      status: distro ? 'warn' : 'danger',
      message: `PHP ${version.raw} はサポート終了(EOL)ブランチで、${CVE_IDS.join(' / ')} の公式修正がありません${distroNote}`,
    };
  }
  const fixed = FIXED_VERSIONS[branch];
  if (fixed === undefined) {
    return { status: 'unknown', message: `PHP ${version.raw} は修正版の対応表にないブランチです。公式情報で確認してください` };
  }
  if (version.patch < fixed) {
    return {
      status: distro ? 'warn' : 'danger',
      message: `PHP ${version.raw} は修正版 ${branch}.${fixed} 未満です${distroNote}`,
    };
  }
  return { status: 'ok', message: `PHP ${version.raw} は修正版 ${branch}.${fixed} 以上です` };
}
