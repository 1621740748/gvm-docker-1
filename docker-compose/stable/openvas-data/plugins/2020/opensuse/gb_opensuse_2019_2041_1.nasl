# Copyright (C) 2020 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.852968");
  script_version("2020-01-31T08:04:39+0000");
  script_cve_id("CVE-2019-12155", "CVE-2019-13164", "CVE-2019-14378", "CVE-2019-5008");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-01-31 08:04:39 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-09 09:49:52 +0000 (Thu, 09 Jan 2020)");
  script_name("openSUSE: Security Advisory for qemu (openSUSE-SU-2019:2041-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"openSUSE-SU", value:"2019:2041-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2019-09/msg00000.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu'
  package(s) announced via the openSUSE-SU-2019:2041-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for qemu fixes the following issues:

  Security issues fixed:

  - CVE-2019-14378: Security fix for heap overflow in ip_reass on big packet
  input (bsc#1143794).

  - CVE-2019-12155: Security fix for null pointer dereference while
  releasing spice resources (bsc#1135902).

  - CVE-2019-13164: Security fix for qemu-bridge-helper ACL can be bypassed
  when names are too long (bsc#1140402).

  - CVE-2019-5008: Fix DoS (NULL pointer dereference) in sparc64 virtual
  machine possible through guest device driver (bsc#1133031).

  Bug fixes and enhancements:

  - Upstream tweaked SnowRidge-Server vcpu model to now be simply Snowridge
  (jsc#SLE-4883)

  - Add SnowRidge-Server vcpu model (jsc#SLE-4883)

  - Add in documentation about md-clear feature (bsc#1138534)

  - Fix SEV issue where older machine type is not processed correctly
  (bsc#1144087)

  - Fix case of a bad pointer in Xen PV usb support code (bsc#1128106)

  - Further refine arch-capabilities handling to help with security and
  performance in Intel hosts (bsc#1134883, bsc#1135210) (fate#327764)

  - Add support for one more security/performance related vcpu feature
  (bsc#1136778) (fate#327796)

  - Ignore csske for expanding the cpu model (bsc#1136540)

  This update was imported from the SUSE:SLE-15-SP1:Update update project.

  Patch Instructions:

 To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-2041=1");

  script_tag(name:"affected", value:"'qemu' package(s) on openSUSE Leap 15.1.");

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

if(release == "openSUSELeap15.1") {

  if(!isnull(res = isrpmvuln(pkg:"qemu", rpm:"qemu~3.1.1~lp151.7.3.3", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-arm", rpm:"qemu-arm~3.1.1~lp151.7.3.3", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-arm-debuginfo", rpm:"qemu-arm-debuginfo~3.1.1~lp151.7.3.3", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-alsa", rpm:"qemu-audio-alsa~3.1.1~lp151.7.3.3", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-alsa-debuginfo", rpm:"qemu-audio-alsa-debuginfo~3.1.1~lp151.7.3.3", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-oss", rpm:"qemu-audio-oss~3.1.1~lp151.7.3.3", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-oss-debuginfo", rpm:"qemu-audio-oss-debuginfo~3.1.1~lp151.7.3.3", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-pa", rpm:"qemu-audio-pa~3.1.1~lp151.7.3.3", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-pa-debuginfo", rpm:"qemu-audio-pa-debuginfo~3.1.1~lp151.7.3.3", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-sdl", rpm:"qemu-audio-sdl~3.1.1~lp151.7.3.3", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-sdl-debuginfo", rpm:"qemu-audio-sdl-debuginfo~3.1.1~lp151.7.3.3", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-curl", rpm:"qemu-block-curl~3.1.1~lp151.7.3.3", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-curl-debuginfo", rpm:"qemu-block-curl-debuginfo~3.1.1~lp151.7.3.3", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-dmg", rpm:"qemu-block-dmg~3.1.1~lp151.7.3.3", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-dmg-debuginfo", rpm:"qemu-block-dmg-debuginfo~3.1.1~lp151.7.3.3", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-gluster", rpm:"qemu-block-gluster~3.1.1~lp151.7.3.3", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-gluster-debuginfo", rpm:"qemu-block-gluster-debuginfo~3.1.1~lp151.7.3.3", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-iscsi", rpm:"qemu-block-iscsi~3.1.1~lp151.7.3.3", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-iscsi-debuginfo", rpm:"qemu-block-iscsi-debuginfo~3.1.1~lp151.7.3.3", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-nfs", rpm:"qemu-block-nfs~3.1.1~lp151.7.3.3", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-nfs-debuginfo", rpm:"qemu-block-nfs-debuginfo~3.1.1~lp151.7.3.3", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-rbd", rpm:"qemu-block-rbd~3.1.1~lp151.7.3.3", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-rbd-debuginfo", rpm:"qemu-block-rbd-debuginfo~3.1.1~lp151.7.3.3", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-ssh", rpm:"qemu-block-ssh~3.1.1~lp151.7.3.3", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-ssh-debuginfo", rpm:"qemu-block-ssh-debuginfo~3.1.1~lp151.7.3.3", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-debuginfo", rpm:"qemu-debuginfo~3.1.1~lp151.7.3.3", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-debugsource", rpm:"qemu-debugsource~3.1.1~lp151.7.3.3", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-extra", rpm:"qemu-extra~3.1.1~lp151.7.3.3", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-extra-debuginfo", rpm:"qemu-extra-debuginfo~3.1.1~lp151.7.3.3", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-guest-agent", rpm:"qemu-guest-agent~3.1.1~lp151.7.3.3", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-guest-agent-debuginfo", rpm:"qemu-guest-agent-debuginfo~3.1.1~lp151.7.3.3", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ksm", rpm:"qemu-ksm~3.1.1~lp151.7.3.3", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~3.1.1~lp151.7.3.3", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-lang", rpm:"qemu-lang~3.1.1~lp151.7.3.3", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-linux-user", rpm:"qemu-linux-user~3.1.1~lp151.7.3.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-linux-user-debuginfo", rpm:"qemu-linux-user-debuginfo~3.1.1~lp151.7.3.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-linux-user-debugsource", rpm:"qemu-linux-user-debugsource~3.1.1~lp151.7.3.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ppc", rpm:"qemu-ppc~3.1.1~lp151.7.3.3", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ppc-debuginfo", rpm:"qemu-ppc-debuginfo~3.1.1~lp151.7.3.3", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-s390", rpm:"qemu-s390~3.1.1~lp151.7.3.3", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-s390-debuginfo", rpm:"qemu-s390-debuginfo~3.1.1~lp151.7.3.3", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-testsuite", rpm:"qemu-testsuite~3.1.1~lp151.7.3.3", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-tools", rpm:"qemu-tools~3.1.1~lp151.7.3.3", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-tools-debuginfo", rpm:"qemu-tools-debuginfo~3.1.1~lp151.7.3.3", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-curses", rpm:"qemu-ui-curses~3.1.1~lp151.7.3.3", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-curses-debuginfo", rpm:"qemu-ui-curses-debuginfo~3.1.1~lp151.7.3.3", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-gtk", rpm:"qemu-ui-gtk~3.1.1~lp151.7.3.3", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-gtk-debuginfo", rpm:"qemu-ui-gtk-debuginfo~3.1.1~lp151.7.3.3", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-sdl", rpm:"qemu-ui-sdl~3.1.1~lp151.7.3.3", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-sdl-debuginfo", rpm:"qemu-ui-sdl-debuginfo~3.1.1~lp151.7.3.3", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-x86", rpm:"qemu-x86~3.1.1~lp151.7.3.3", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-x86-debuginfo", rpm:"qemu-x86-debuginfo~3.1.1~lp151.7.3.3", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ipxe", rpm:"qemu-ipxe~1.0.0+~lp151.7.3.3", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-seabios", rpm:"qemu-seabios~1.12.0~lp151.7.3.3", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-sgabios", rpm:"qemu-sgabios~8~lp151.7.3.3", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-vgabios", rpm:"qemu-vgabios~1.12.0~lp151.7.3.3", rls:"openSUSELeap15.1"))) {
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
