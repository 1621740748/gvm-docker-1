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
  script_oid("1.3.6.1.4.1.25623.1.0.853851");
  script_version("2021-06-17T06:11:17+0000");
  script_cve_id("CVE-2020-24586", "CVE-2020-24587", "CVE-2020-24588", "CVE-2020-26139", "CVE-2020-26141", "CVE-2020-26145", "CVE-2020-26147", "CVE-2021-23134", "CVE-2021-32399", "CVE-2021-33034", "CVE-2021-33200", "CVE-2021-3491");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-06-17 06:11:17 +0000 (Thu, 17 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-06-07 03:01:18 +0000 (Mon, 07 Jun 2021)");
  script_name("openSUSE: Security Advisory for the (openSUSE-SU-2021:0843-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:0843-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/QHZZYSYX2W3FJK73UGT72F2DQ37IKCJY");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the'
  package(s) announced via the openSUSE-SU-2021:0843-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The openSUSE Leap 15.2 kernel was updated to receive various security and
     bugfixes.


     The following security bugs were fixed:

  - CVE-2021-33200: Enforcing incorrect limits for pointer arithmetic
       operations by the BPF verifier could be abused to perform out-of-bounds
       reads and writes in kernel memory (bsc#1186484).

  - CVE-2021-33034: Fixed a use-after-free when destroying an hci_chan. This
       could lead to writing an arbitrary values. (bsc#1186111)

  - CVE-2020-26139: Fixed a denial-of-service when an Access Point (AP)
       forwards EAPOL frames to other clients even though the sender has not
       yet successfully authenticated to the AP. (bnc#1186062)

  - CVE-2021-23134: A Use After Free vulnerability in nfc sockets allowed
       local attackers to elevate their privileges. (bnc#1186060)

  - CVE-2021-3491: Fixed a potential heap overflow in mem_rw(). This
       vulnerability is related to the PROVIDE_BUFFERS operation, which allowed
       the MAX_RW_COUNT limit to be bypassed (bsc#1185642).

  - CVE-2021-32399: Fixed a race condition when removing the HCI controller
       (bnc#1184611).

  - CVE-2020-24586: The 802.11 standard that underpins Wi-Fi Protected
       Access (WPA, WPA2, and WPA3) and Wired Equivalent Privacy (WEP) doesn&#x27 t
       require that received fragments be cleared from memory after
       (re)connecting to a network. Under the right circumstances this can be
       abused to inject arbitrary network packets and/or exfiltrate user data
       (bnc#1185859).

  - CVE-2020-24587: The 802.11 standard that underpins Wi-Fi Protected
       Access (WPA, WPA2, and WPA3) and Wired Equivalent Privacy (WEP) doesn&#x27 t
       require that all fragments of a frame are encrypted under the same key.
       An adversary can abuse this to decrypt selected fragments when another
       device sends fragmented frames and the WEP, CCMP, or GCMP encryption key
       is periodically renewed (bnc#1185859 bnc#1185862).

  - CVE-2020-24588: The 802.11 standard that underpins Wi-Fi Protected
       Access (WPA, WPA2, and WPA3) and Wired Equivalent Privacy (WEP) doesn&#x27 t
       require that the A-MSDU flag in the plaintext QoS header field is
       authenticated. Against devices that support receiving non-SSP A-MSDU
       frames (which is mandatory as part of 802.11n), an adversary can abuse
       this to inject arbitrary network packets. (bnc#1185861)

  - CVE-2020-26147: The WEP, WPA, WPA2, and WPA3 implementations reassemble
       fragments, even though some of them were sent in plaintext. This
       vulnerabili ...

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.3.18~lp152.78.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.3.18~lp152.78.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs-html", rpm:"kernel-docs-html~5.3.18~lp152.78.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.3.18~lp152.78.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.3.18~lp152.78.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-vanilla", rpm:"kernel-source-vanilla~5.3.18~lp152.78.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~5.3.18~lp152.78.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-debuginfo", rpm:"kernel-debug-debuginfo~5.3.18~lp152.78.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-debugsource", rpm:"kernel-debug-debugsource~5.3.18~lp152.78.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~5.3.18~lp152.78.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel-debuginfo", rpm:"kernel-debug-devel-debuginfo~5.3.18~lp152.78.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.3.18~lp152.78.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.3.18~lp152.78.1.lp152.8.34.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base-rebuild", rpm:"kernel-default-base-rebuild~5.3.18~lp152.78.1.lp152.8.34.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~5.3.18~lp152.78.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~5.3.18~lp152.78.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.3.18~lp152.78.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel-debuginfo", rpm:"kernel-default-devel-debuginfo~5.3.18~lp152.78.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall", rpm:"kernel-kvmsmall~5.3.18~lp152.78.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-debuginfo", rpm:"kernel-kvmsmall-debuginfo~5.3.18~lp152.78.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-debugsource", rpm:"kernel-kvmsmall-debugsource~5.3.18~lp152.78.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-devel", rpm:"kernel-kvmsmall-devel~5.3.18~lp152.78.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-devel-debuginfo", rpm:"kernel-kvmsmall-devel-debuginfo~5.3.18~lp152.78.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.3.18~lp152.78.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build-debugsource", rpm:"kernel-obs-build-debugsource~5.3.18~lp152.78.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-qa", rpm:"kernel-obs-qa~5.3.18~lp152.78.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt", rpm:"kernel-preempt~5.3.18~lp152.78.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-debuginfo", rpm:"kernel-preempt-debuginfo~5.3.18~lp152.78.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-debugsource", rpm:"kernel-preempt-debugsource~5.3.18~lp152.78.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel", rpm:"kernel-preempt-devel~5.3.18~lp152.78.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel-debuginfo", rpm:"kernel-preempt-devel-debuginfo~5.3.18~lp152.78.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.3.18~lp152.78.1", rls:"openSUSELeap15.2"))) {
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