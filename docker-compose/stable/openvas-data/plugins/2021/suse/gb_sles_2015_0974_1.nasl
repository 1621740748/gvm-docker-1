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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.0974.1");
  script_cve_id("CVE-2013-5704", "CVE-2014-3581", "CVE-2014-8109", "CVE-2015-0228");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-06 11:15:00 +0000 (Sun, 06 Jun 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:0974-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:0974-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20150974-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache2' package(s) announced via the SUSE-SU-2015:0974-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Apache2 updated to fix four security issues and one non-security bug.
The following vulnerabilities have been fixed:
- mod_headers rules could be bypassed via chunked requests. Adds
 'MergeTrailers' directive to restore legacy behavior. (bsc#871310,
 CVE-2013-5704)
- An empty value in Content-Type could lead to a crash through a null
 pointer dereference and a denial of service. (bsc#899836, CVE-2014-3581)
- Remote attackers could bypass intended access restrictions in mod_lua
 LuaAuthzProvider when multiple Require directives with different
 arguments are used. (bsc#909715, CVE-2014-8109)
- Remote attackers could cause a denial of service (child-process crash)
 by sending a crafted WebSocket Ping frame after a Lua script has called
 the wsupgrade function. (bsc#918352, CVE-2015-0228)
The following non-security issues have been fixed:
- The Apache2 systemd service file was changed to fix situation where
 apache wouldn't start at boot when using an encrypted certificate
 because the user wasn't prompted for password during boot. (bsc#792309)
Additionally, mod_imagemap is now included by default in the package.
(bsc#923090)");

  script_tag(name:"affected", value:"'apache2' package(s) on SUSE Linux Enterprise Software Development Kit 12, SUSE Linux Enterprise Server 12.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"apache2", rpm:"apache2~2.4.10~12.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-debuginfo", rpm:"apache2-debuginfo~2.4.10~12.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-debugsource", rpm:"apache2-debugsource~2.4.10~12.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-example-pages", rpm:"apache2-example-pages~2.4.10~12.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-prefork", rpm:"apache2-prefork~2.4.10~12.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-prefork-debuginfo", rpm:"apache2-prefork-debuginfo~2.4.10~12.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-utils", rpm:"apache2-utils~2.4.10~12.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-utils-debuginfo", rpm:"apache2-utils-debuginfo~2.4.10~12.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-worker", rpm:"apache2-worker~2.4.10~12.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-worker-debuginfo", rpm:"apache2-worker-debuginfo~2.4.10~12.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-doc", rpm:"apache2-doc~2.4.10~12.1", rls:"SLES12.0"))) {
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
