# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.853473");
  script_version("2020-10-08T07:56:44+0000");
  script_cve_id("CVE-2020-0404", "CVE-2020-0427", "CVE-2020-0431", "CVE-2020-0432", "CVE-2020-14385", "CVE-2020-14390", "CVE-2020-2521", "CVE-2020-25284", "CVE-2020-26088");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-10-08 07:56:44 +0000 (Thu, 08 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-10-02 03:00:59 +0000 (Fri, 02 Oct 2020)");
  script_name("openSUSE: Security Advisory for the (openSUSE-SU-2020:1586-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"openSUSE-SU", value:"2020:1586-1");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00001.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the'
  package(s) announced via the openSUSE-SU-2020:1586-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The openSUSE Leap 15.2 kernel was updated to receive various security and
  bugfixes.

  The following security bugs were fixed:

  - CVE-2020-0404: In uvc_scan_chain_forward of uvc_driver.c, there is a
  possible linked list corruption due to an unusual root cause. This could
  lead to local escalation of privilege in the kernel with no additional
  execution privileges needed. User interaction is not needed for
  exploitation (bnc#1176423).

  - CVE-2020-0427: In create_pinctrl of core.c, there is a possible out of
  bounds read due to a use after free. This could lead to local
  information disclosure with no additional execution privileges needed.
  User interaction is not needed for exploitation (bnc#1176725).

  - CVE-2020-0431: In kbd_keycode of keyboard.c, there is a possible out of
  bounds write due to a missing bounds check. This could lead to local
  escalation of privilege with no additional execution privileges needed.
  User interaction is not needed for exploitation (bnc#1176722).

  - CVE-2020-0432: In skb_to_mamac of networking.c, there is a possible out
  of bounds write due to an integer overflow. This could lead to local
  escalation of privilege with no additional execution privileges needed.
  User interaction is not needed for exploitation (bnc#1176721).

  - CVE-2020-14385: Fixed a boundary test in xfs_attr_shortform_verify which
  could lead to crashes (bsc#1176137).

  - CVE-2020-14390: When changing screen size, an out-of-bounds memory write
  can occur leading to memory corruption or a denial of service. Due to
  the nature of the flaw, privilege escalation cannot be fully ruled out
  (bnc#1176235).

  - CVE-2020-2521: Fixed a getxattr kernel panic and memory overflow in
  NFS4(bsc#1176381).

  - CVE-2020-25284: Require global CAP_SYS_ADMIN for mapping and unmapping
  rbd devices (bsc#1176543).

  - CVE-2020-26088: A missing CAP_NET_RAW check in NFC socket creation in
  net/nfc/rawsock.c could be used by local attackers to create raw
  sockets, bypassing security mechanisms, aka CID-26896f01467a
  (bnc#1176990).

  The following non-security bugs were fixed:

  - ALSA: asihpi: fix iounmap in error handler (git-fixes).

  - ALSA: ca0106: fix error code handling (git-fixes).

  - ALSA: firewire-digi00x: exclude Avid Adrenaline from detection
  (git-fixes).

  - ALSA, firewire-tascam: exclude Tascam FE-8 from detection (git-fixes).

  - ALSA: hda: Fix 2 channel swapping for Tegra (git-fixes).

  - ALSA: hda: fix a runtime pm issue in SOF when integrated GPU is disabled
  (git-fixes).

  - ALSA: hda - Fix silent audio output and corrupted input on MSI X570-A
  PRO (git-fixes).
   ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'the' package(s) on openSUSE Leap 15.2.");

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

if(release == "openSUSELeap15.2") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~5.3.18~lp152.44.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-debuginfo", rpm:"kernel-debug-debuginfo~5.3.18~lp152.44.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-debugsource", rpm:"kernel-debug-debugsource~5.3.18~lp152.44.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~5.3.18~lp152.44.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel-debuginfo", rpm:"kernel-debug-devel-debuginfo~5.3.18~lp152.44.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.3.18~lp152.44.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.3.18~lp152.44.1.lp152.8.8.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base-rebuild", rpm:"kernel-default-base-rebuild~5.3.18~lp152.44.1.lp152.8.8.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~5.3.18~lp152.44.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~5.3.18~lp152.44.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.3.18~lp152.44.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel-debuginfo", rpm:"kernel-default-devel-debuginfo~5.3.18~lp152.44.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall", rpm:"kernel-kvmsmall~5.3.18~lp152.44.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-debuginfo", rpm:"kernel-kvmsmall-debuginfo~5.3.18~lp152.44.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-debugsource", rpm:"kernel-kvmsmall-debugsource~5.3.18~lp152.44.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-devel", rpm:"kernel-kvmsmall-devel~5.3.18~lp152.44.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-devel-debuginfo", rpm:"kernel-kvmsmall-devel-debuginfo~5.3.18~lp152.44.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.3.18~lp152.44.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build-debugsource", rpm:"kernel-obs-build-debugsource~5.3.18~lp152.44.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-qa", rpm:"kernel-obs-qa~5.3.18~lp152.44.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt", rpm:"kernel-preempt~5.3.18~lp152.44.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-debuginfo", rpm:"kernel-preempt-debuginfo~5.3.18~lp152.44.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-debugsource", rpm:"kernel-preempt-debugsource~5.3.18~lp152.44.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel", rpm:"kernel-preempt-devel~5.3.18~lp152.44.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel-debuginfo", rpm:"kernel-preempt-devel-debuginfo~5.3.18~lp152.44.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.3.18~lp152.44.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.3.18~lp152.44.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.3.18~lp152.44.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs-html", rpm:"kernel-docs-html~5.3.18~lp152.44.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.3.18~lp152.44.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.3.18~lp152.44.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-vanilla", rpm:"kernel-source-vanilla~5.3.18~lp152.44.1", rls:"openSUSELeap15.2"))) {
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