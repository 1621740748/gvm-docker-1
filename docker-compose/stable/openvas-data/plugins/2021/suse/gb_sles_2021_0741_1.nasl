# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.0741.1");
  script_cve_id("CVE-2020-12362", "CVE-2020-12363", "CVE-2020-12364", "CVE-2020-12373", "CVE-2020-29368", "CVE-2020-29374", "CVE-2021-26930", "CVE-2021-26931", "CVE-2021-26932");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:42 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-22 18:07:00 +0000 (Mon, 22 Feb 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:0741-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:0741-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20210741-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2021:0741-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP2 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

CVE-2021-26930: Fixed an improper error handling in blkback's grant
 mapping (XSA-365 bsc#1181843).

CVE-2021-26931: Fixed an issue where Linux kernel was treating grant
 mapping errors as bugs (XSA-362 bsc#1181753).

CVE-2021-26932: Fixed improper error handling issues in Linux grant
 mapping (XSA-361 bsc#1181747). by remote attackers to read or write
 files via directory traversal in an XCOPY request (bsc#178372).

CVE-2020-12362: Fixed an integer overflow in the firmware which may have
 allowed a privileged user to potentially enable an escalation of
 privilege via local access (bsc#1181720).

CVE-2020-12363: Fixed an improper input validation which may have
 allowed a privileged user to potentially enable a denial of service via
 local access (bsc#1181735).

CVE-2020-12364: Fixed a null pointer reference which may have allowed a
 privileged user to potentially enable a denial of service via local
 access (bsc#1181736 ).

CVE-2020-12373: Fixed an expired pointer dereference which may have
 allowed a privileged user to potentially enable a denial of service via
 local access (bsc#1181738).

CVE-2020-29368,CVE-2020-29374: Fixed an issue in copy-on-write
 implementation which could have granted unintended write access because
 of a race condition in a THP mapcount check (bsc#1179660, bsc#1179428).

The following non-security bugs were fixed:

ACPI: configfs: add missing check after
 configfs_register_default_group() (git-fixes).

ACPI: property: Fix fwnode string properties matching (git-fixes).

ACPI: property: Satisfy kernel doc validator (part 1) (git-fixes).

ACPI: property: Satisfy kernel doc validator (part 2) (git-fixes).

ALSA: hda: Add another CometLake-H PCI ID (git-fixes).

ALSA: hda/hdmi: Drop bogus check at closing a stream (git-fixes).

ALSA: hda/realtek: modify EAPD in the ALC886 (git-fixes).

ALSA: pcm: Assure sync with the pending stop operation at suspend
 (git-fixes).

ALSA: pcm: Call sync_stop at disconnection (git-fixes).

ALSA: pcm: Do not call sync_stop if it hasn't been stopped (git-fixes).

ALSA: usb-audio: Add implicit fb quirk for BOSS GP-10 (git-fixes).

ALSA: usb-audio: Correct document for snd_usb_endpoint_free_all()
 (git-fixes).

ALSA: usb-audio: Do not avoid stopping the stream at disconnection
 (git-fixes).

ALSA: usb-audio: Fix PCM buffer allocation in non-vmalloc mode
 (git-fixes).

ALSA: usb-audio: Handle invalid running state at releasing EP
 (git-fixes).

ALSA: usb-audio: More strict state change in EP (git-fixes).

amba: Fix resource leak for drivers without .remove (git-fixes).

arm64: Update config file. Set CONFIG_WATCHDOG_SYSFS to true
 (bsc#1182560)

ASoC: cpcap: fix microphone timeslot mask (git-fixes).

ASoC: cs42l56: fix up error handling in probe (git-fixes).

ASoC: simple-card-utils: Fix ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE MicroOS 5.0, SUSE Linux Enterprise Workstation Extension 15-SP2, SUSE Linux Enterprise Module for Live Patching 15-SP2, SUSE Linux Enterprise Module for Legacy Software 15-SP2, SUSE Linux Enterprise Module for Development Tools 15-SP2, SUSE Linux Enterprise Module for Basesystem 15-SP2, SUSE Linux Enterprise High Availability 15-SP2.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~5.3.18~24.52.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~5.3.18~24.52.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.3.18~24.52.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default-debuginfo", rpm:"reiserfs-kmp-default-debuginfo~5.3.18~24.52.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.3.18~24.52.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build-debugsource", rpm:"kernel-obs-build-debugsource~5.3.18~24.52.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.3.18~24.52.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-debuginfo", rpm:"kernel-preempt-debuginfo~5.3.18~24.52.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-debugsource", rpm:"kernel-preempt-debugsource~5.3.18~24.52.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel", rpm:"kernel-preempt-devel~5.3.18~24.52.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel-debuginfo", rpm:"kernel-preempt-devel-debuginfo~5.3.18~24.52.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.3.18~24.52.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.3.18~24.52.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.3.18~24.52.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.3.18~24.52.1.9.24.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.3.18~24.52.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel-debuginfo", rpm:"kernel-default-devel-debuginfo~5.3.18~24.52.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt", rpm:"kernel-preempt~5.3.18~24.52.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.3.18~24.52.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.3.18~24.52.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
