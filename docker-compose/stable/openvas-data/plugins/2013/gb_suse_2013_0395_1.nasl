# Copyright (C) 2013 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of their respective author(s)
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
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2013-03/msg00004.html");
  script_oid("1.3.6.1.4.1.25623.1.0.850425");
  script_version("2020-01-31T08:23:39+0000");
  script_tag(name:"last_modification", value:"2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2013-03-11 18:29:24 +0530 (Mon, 11 Mar 2013)");
  script_cve_id("CVE-2012-5374", "CVE-2013-0160", "CVE-2013-0216", "CVE-2013-0231",
                "CVE-2013-1763");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name:"openSUSE-SU", value:"2013:0395-1");
  script_name("openSUSE: Security Advisory for kernel (openSUSE-SU-2013:0395-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE12\.2");

  script_tag(name:"affected", value:"kernel on openSUSE 12.2");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"insight", value:"The Linux kernel was updated to 3.4.33 and to fix a local
  root privilege escalation and various other security and
  non-security bugs.

  CVE-2013-1763: A out of bounds access in sock_diag could be
  used by local attackers to execute code in kernel context
  and so become root.

  CVE-2013-0160: The atime of /dev/ptmx is no longer updated,
  avoiding side channel attacks via user typing speed.

  CVE-2012-5374: Denial of service via btrfs hashes could
  have been used by local attackers to cause a compute denial
  of service.

  CVE-2013-0216: Fixed a problem in XEN netback: shutdown the
  ring if it contains garbage.

  CVE-2013-0231: Fixed a problem in XEN pciback: rate limit
  error messages from xen_pcibk_enable_msi(x).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSE12.2") {
  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.4.33~2.24.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.4.33~2.24.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base-debuginfo", rpm:"kernel-default-base-debuginfo~3.4.33~2.24.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~3.4.33~2.24.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~3.4.33~2.24.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.4.33~2.24.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel-debuginfo", rpm:"kernel-default-devel-debuginfo~3.4.33~2.24.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.4.33~2.24.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~3.4.33~2.24.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-base", rpm:"kernel-debug-base~3.4.33~2.24.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-base-debuginfo", rpm:"kernel-debug-base-debuginfo~3.4.33~2.24.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-debuginfo", rpm:"kernel-debug-debuginfo~3.4.33~2.24.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-debugsource", rpm:"kernel-debug-debugsource~3.4.33~2.24.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~3.4.33~2.24.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel-debuginfo", rpm:"kernel-debug-devel-debuginfo~3.4.33~2.24.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop", rpm:"kernel-desktop~3.4.33~2.24.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-base", rpm:"kernel-desktop-base~3.4.33~2.24.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-base-debuginfo", rpm:"kernel-desktop-base-debuginfo~3.4.33~2.24.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-debuginfo", rpm:"kernel-desktop-debuginfo~3.4.33~2.24.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-debugsource", rpm:"kernel-desktop-debugsource~3.4.33~2.24.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-devel", rpm:"kernel-desktop-devel~3.4.33~2.24.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-devel-debuginfo", rpm:"kernel-desktop-devel-debuginfo~3.4.33~2.24.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.4.33~2.24.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~3.4.33~2.24.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base-debuginfo", rpm:"kernel-ec2-base-debuginfo~3.4.33~2.24.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debuginfo", rpm:"kernel-ec2-debuginfo~3.4.33~2.24.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debugsource", rpm:"kernel-ec2-debugsource~3.4.33~2.24.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.4.33~2.24.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel-debuginfo", rpm:"kernel-ec2-devel-debuginfo~3.4.33~2.24.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-extra", rpm:"kernel-ec2-extra~3.4.33~2.24.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-extra-debuginfo", rpm:"kernel-ec2-extra-debuginfo~3.4.33~2.24.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~3.4.33~2.24.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~3.4.33~2.24.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base-debuginfo", rpm:"kernel-trace-base-debuginfo~3.4.33~2.24.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-debuginfo", rpm:"kernel-trace-debuginfo~3.4.33~2.24.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-debugsource", rpm:"kernel-trace-debugsource~3.4.33~2.24.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~3.4.33~2.24.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel-debuginfo", rpm:"kernel-trace-devel-debuginfo~3.4.33~2.24.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla", rpm:"kernel-vanilla~3.4.33~2.24.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-debuginfo", rpm:"kernel-vanilla-debuginfo~3.4.33~2.24.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-debugsource", rpm:"kernel-vanilla-debugsource~3.4.33~2.24.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-devel", rpm:"kernel-vanilla-devel~3.4.33~2.24.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-devel-debuginfo", rpm:"kernel-vanilla-devel-debuginfo~3.4.33~2.24.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.4.33~2.24.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.4.33~2.24.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base-debuginfo", rpm:"kernel-xen-base-debuginfo~3.4.33~2.24.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-debuginfo", rpm:"kernel-xen-debuginfo~3.4.33~2.24.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-debugsource", rpm:"kernel-xen-debugsource~3.4.33~2.24.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.4.33~2.24.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel-debuginfo", rpm:"kernel-xen-devel-debuginfo~3.4.33~2.24.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.4.33~2.24.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~3.4.33~2.24.2", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.4.33~2.24.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-vanilla", rpm:"kernel-source-vanilla~3.4.33~2.24.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~3.4.33~2.24.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~3.4.33~2.24.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-base-debuginfo", rpm:"kernel-pae-base-debuginfo~3.4.33~2.24.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-debuginfo", rpm:"kernel-pae-debuginfo~3.4.33~2.24.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-debugsource", rpm:"kernel-pae-debugsource~3.4.33~2.24.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-devel", rpm:"kernel-pae-devel~3.4.33~2.24.1", rls:"openSUSE12.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-devel-debuginfo", rpm:"kernel-pae-devel-debuginfo~3.4.33~2.24.1", rls:"openSUSE12.2"))) {
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
