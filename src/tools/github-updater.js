/**
 * GitHub Updater
 *
 * Allows Guardian-Agent to check for and install updates from GitHub.
 * Keeps the plugin and vulnerability databases current.
 */

import { execSync } from 'child_process';
import { readFile, writeFile, access } from 'fs/promises';
import { join } from 'path';

export class GitHubUpdater {
  constructor(projectPath) {
    this.projectPath = projectPath;
    this.repoUrl = 'https://github.com/naieum/ChiefWiggum';
    this.rawUrl = 'https://raw.githubusercontent.com/naieum/ChiefWiggum/main';
  }

  /**
   * Check for updates from GitHub
   */
  async checkForUpdates() {
    console.error('[Updater] Checking for updates...');

    try {
      // Get current version
      const currentVersion = await this.getCurrentVersion();

      // Fetch latest version from GitHub
      const latestVersion = await this.getLatestVersion();

      if (!latestVersion) {
        return {
          success: false,
          error: 'Could not fetch latest version from GitHub'
        };
      }

      const updateAvailable = this.compareVersions(currentVersion, latestVersion.version) < 0;

      // Get changelog if update available
      let changelog = null;
      if (updateAvailable) {
        changelog = await this.getChangelog();
      }

      return {
        success: true,
        current_version: currentVersion,
        latest_version: latestVersion.version,
        update_available: updateAvailable,
        changelog: changelog,
        release_notes: latestVersion.description,
        update_command: updateAvailable ? 'Use the `update_guardian_agent` tool to update' : null,
        repository: this.repoUrl
      };

    } catch (err) {
      return {
        success: false,
        error: `Failed to check for updates: ${err.message}`
      };
    }
  }

  /**
   * Update Guardian-Agent from GitHub
   */
  async update(options = {}) {
    const { force = false, backup = true } = options;

    console.error('[Updater] Starting update...');

    try {
      // Check if we're in a git repo
      const isGitRepo = await this.isGitRepository();

      if (isGitRepo) {
        return await this.updateViaGit(options);
      } else {
        return await this.updateViaDownload(options);
      }

    } catch (err) {
      return {
        success: false,
        error: `Update failed: ${err.message}`
      };
    }
  }

  /**
   * Update via git pull
   */
  async updateViaGit(options = {}) {
    const { force = false } = options;

    console.error('[Updater] Updating via git...');

    try {
      // Check for local changes
      const status = execSync('git status --porcelain', {
        cwd: this.projectPath,
        encoding: 'utf-8'
      }).trim();

      if (status && !force) {
        return {
          success: false,
          error: 'Local changes detected. Use force: true to override, or commit/stash changes first.',
          local_changes: status.split('\n').slice(0, 10)
        };
      }

      // Fetch latest
      execSync('git fetch origin', {
        cwd: this.projectPath,
        encoding: 'utf-8'
      });

      // Get current branch
      const branch = execSync('git rev-parse --abbrev-ref HEAD', {
        cwd: this.projectPath,
        encoding: 'utf-8'
      }).trim();

      // Check if we're behind
      const behind = execSync(`git rev-list HEAD..origin/${branch} --count`, {
        cwd: this.projectPath,
        encoding: 'utf-8'
      }).trim();

      if (behind === '0') {
        return {
          success: true,
          message: 'Already up to date',
          version: await this.getCurrentVersion()
        };
      }

      // Stash local changes if force
      if (status && force) {
        execSync('git stash', {
          cwd: this.projectPath,
          encoding: 'utf-8'
        });
      }

      // Pull latest
      const pullOutput = execSync(`git pull origin ${branch}`, {
        cwd: this.projectPath,
        encoding: 'utf-8'
      });

      // Get new version
      const newVersion = await this.getCurrentVersion();

      return {
        success: true,
        message: 'Updated successfully via git',
        previous_version: await this.getCurrentVersion(),
        new_version: newVersion,
        commits_pulled: parseInt(behind),
        output: pullOutput.trim()
      };

    } catch (err) {
      return {
        success: false,
        error: `Git update failed: ${err.message}`
      };
    }
  }

  /**
   * Update via direct download (for non-git installations)
   */
  async updateViaDownload(options = {}) {
    const { backup = true } = options;

    console.error('[Updater] Updating via download...');

    const filesToUpdate = [
      'app/server.js',
      'src/analyzers/live-cve-checker.js',
      'src/analyzers/stack-detector.js',
      'src/analyzers/static.js',
      'src/tools/security-score.js',
      'src/tools/env-auditor.js',
      'src/tools/security-fix-generator.js',
      'src/tools/pre-commit-hook.js',
      '.claude-plugin/plugin.json'
    ];

    const updated = [];
    const failed = [];

    for (const file of filesToUpdate) {
      try {
        const url = `${this.rawUrl}/${file}`;
        const response = await fetch(url);

        if (!response.ok) {
          failed.push({ file, error: `HTTP ${response.status}` });
          continue;
        }

        const content = await response.text();
        const filePath = join(this.projectPath, file);

        // Backup existing file
        if (backup) {
          try {
            const existing = await readFile(filePath, 'utf-8');
            await writeFile(`${filePath}.backup`, existing);
          } catch {
            // File doesn't exist, no backup needed
          }
        }

        // Write new content
        await writeFile(filePath, content);
        updated.push(file);

      } catch (err) {
        failed.push({ file, error: err.message });
      }
    }

    return {
      success: failed.length === 0,
      message: failed.length === 0 ? 'Updated successfully' : 'Partial update',
      files_updated: updated,
      files_failed: failed,
      new_version: await this.getCurrentVersion()
    };
  }

  /**
   * Update only the vulnerability databases
   */
  async updateVulnDatabases() {
    console.error('[Updater] Updating vulnerability databases...');

    const databases = [
      'src/analyzers/live-cve-checker.js'
    ];

    const updated = [];

    for (const file of databases) {
      try {
        const url = `${this.rawUrl}/${file}`;
        const response = await fetch(url);

        if (response.ok) {
          const content = await response.text();
          await writeFile(join(this.projectPath, file), content);
          updated.push(file);
        }
      } catch (err) {
        console.error(`[Updater] Failed to update ${file}: ${err.message}`);
      }
    }

    return {
      success: true,
      message: 'Vulnerability databases updated',
      updated_files: updated,
      note: 'Live CVE data is always fetched fresh from OSV API'
    };
  }

  /**
   * Get current installed version
   */
  async getCurrentVersion() {
    try {
      const pluginJson = await readFile(
        join(this.projectPath, '.claude-plugin', 'plugin.json'),
        'utf-8'
      );
      const plugin = JSON.parse(pluginJson);
      return plugin.version || '0.0.0';
    } catch {
      // Try package.json
      try {
        const packageJson = await readFile(
          join(this.projectPath, 'package.json'),
          'utf-8'
        );
        const pkg = JSON.parse(packageJson);
        return pkg.version || '0.0.0';
      } catch {
        return '0.0.0';
      }
    }
  }

  /**
   * Get latest version from GitHub
   */
  async getLatestVersion() {
    try {
      // Try to get from plugin.json on main branch
      const response = await fetch(
        `${this.rawUrl}/.claude-plugin/plugin.json`
      );

      if (response.ok) {
        const plugin = await response.json();
        return {
          version: plugin.version,
          description: plugin.description
        };
      }

      // Fallback: try package.json
      const pkgResponse = await fetch(`${this.rawUrl}/package.json`);
      if (pkgResponse.ok) {
        const pkg = await pkgResponse.json();
        return {
          version: pkg.version,
          description: pkg.description
        };
      }

      return null;
    } catch {
      return null;
    }
  }

  /**
   * Get changelog from GitHub
   */
  async getChangelog() {
    try {
      const response = await fetch(`${this.rawUrl}/CHANGELOG.md`);
      if (response.ok) {
        const content = await response.text();
        // Return first 1000 chars
        return content.substring(0, 1000);
      }
    } catch {
      // No changelog
    }
    return null;
  }

  /**
   * Check if project is a git repository
   */
  async isGitRepository() {
    try {
      await access(join(this.projectPath, '.git'));
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Compare semantic versions
   * Returns: -1 if a < b, 0 if a === b, 1 if a > b
   */
  compareVersions(a, b) {
    const pa = a.split('.').map(x => parseInt(x) || 0);
    const pb = b.split('.').map(x => parseInt(x) || 0);

    for (let i = 0; i < 3; i++) {
      if ((pa[i] || 0) < (pb[i] || 0)) return -1;
      if ((pa[i] || 0) > (pb[i] || 0)) return 1;
    }
    return 0;
  }

  /**
   * Get GitHub releases
   */
  async getReleases() {
    try {
      const response = await fetch(
        'https://api.github.com/repos/naieum/ChiefWiggum/releases',
        {
          headers: {
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'Guardian-Agent'
          }
        }
      );

      if (response.ok) {
        const releases = await response.json();
        return releases.slice(0, 5).map(r => ({
          version: r.tag_name,
          name: r.name,
          published: r.published_at,
          notes: r.body?.substring(0, 500)
        }));
      }
    } catch {
      // API rate limited or unavailable
    }
    return [];
  }
}

export default GitHubUpdater;
