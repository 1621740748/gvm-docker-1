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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.2908.1");
  script_cve_id("CVE-2020-0404", "CVE-2020-0427", "CVE-2020-0431", "CVE-2020-0432", "CVE-2020-14385", "CVE-2020-14390", "CVE-2020-25212", "CVE-2020-25284", "CVE-2020-26088");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:52 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-11 21:15:00 +0000 (Sun, 11 Oct 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:2908-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:2908-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20202908-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2020:2908-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP2 Azure kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

CVE-2020-26088: Fixed an improper CAP_NET_RAW check in NFC socket
 creation could have been used by local attackers to create raw sockets,
 bypassing security mechanisms (bsc#1176990).

CVE-2020-14390: Fixed an out-of-bounds memory write leading to memory
 corruption or a denial of service when changing screen size
 (bnc#1176235).

CVE-2020-0432: Fixed an out of bounds write due to an integer overflow
 (bsc#1176721).

CVE-2020-0427: Fixed an out of bounds read due to a use after free
 (bsc#1176725).

CVE-2020-0431: Fixed an out of bounds write due to a missing bounds
 check (bsc#1176722).

CVE-2020-0404: Fixed a linked list corruption due to an unusual root
 cause (bsc#1176423).

CVE-2020-25212: Fixed getxattr kernel panic and memory overflow
 (bsc#1176381).

CVE-2020-25284: Fixed an incomplete permission checking for access to
 rbd devices, which could have been leveraged by local attackers to map
 or unmap rbd block devices (bsc#1176482).

CVE-2020-14385: Fixed a failure of the file system metadata validator in
 XFS which could have caused an inode with a valid, user-creatable
 extended attribute to be flagged as corrupt (bsc#1176137).

The following non-security bugs were fixed:

ALSA: asihpi: fix iounmap in error handler (git-fixes).

ALSA: ca0106: fix error code handling (git-fixes).

ALSA: firewire-digi00x: exclude Avid Adrenaline from detection
 (git-fixes).

ALSA, firewire-tascam: exclude Tascam FE-8 from detection (git-fixes).

ALSA: hda: Fix 2 channel swapping for Tegra (git-fixes).

ALSA: hda: fix a runtime pm issue in SOF when integrated GPU is disabled
 (git-fixes).

ALSA: hda - Fix silent audio output and corrupted input on MSI X570-A
 PRO (git-fixes).

ALSA: hda: fixup headset for ASUS GX502 laptop (git-fixes).

ALSA: hda: hdmi - add Rocketlake support (git-fixes).

ALSA: hda/hdmi: always check pin power status in i915 pin fixup
 (git-fixes).

ALSA: hda/realtek: Add quirk for Samsung Galaxy Book Ion NT950XCJ-X716A
 (git-fixes).

ALSA: hda/realtek - Couldn't detect Mic if booting with headset plugged
 (git-fixes).

ALSA: hda/realtek: Enable front panel headset LED on Lenovo ThinkStation
 P520 (git-fixes).

ALSA: hda/realtek - Improved routing for Thinkpad X1 7th/8th Gen
 (git-fixes).

ALSA: hda/realtek - The Mic on a RedmiBook does not work (git-fixes).

ALSA: hda/tegra: Program WAKEEN register for Tegra (git-fixes).

ALSA: pcm: oss: Remove superfluous WARN_ON() for mulaw sanity check
 (git-fixes).

ALSA: usb-audio: Add basic capture support for Pioneer DJ DJM-250MK2
 (git-fixes).

ALSA: usb-audio: Add delay quirk for H570e USB headsets (git-fixes).

ALSA: usb-audio: Add implicit feedback quirk for UR22C (git-fixes).

ALSA: usb-audio: Disable autosuspend for Lenovo ThinkStation P620
 (git-fixes).

arm64: paravirt: ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Module for Public Cloud 15-SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~5.3.18~18.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~5.3.18~18.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~5.3.18~18.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~5.3.18~18.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~5.3.18~18.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~5.3.18~18.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel-debuginfo", rpm:"kernel-azure-devel-debuginfo~5.3.18~18.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~5.3.18~18.21.1", rls:"SLES15.0SP2"))) {
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
