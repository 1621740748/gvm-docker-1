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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2014.0883.1");
  script_cve_id("CVE-2013-1982");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:20 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2013-06-21 03:17:00 +0000 (Fri, 21 Jun 2013)");

  script_name("SUSE: Security Advisory (SUSE-SU-2014:0883-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2014:0883-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2014/suse-su-20140883-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xorg-x11-libXext' package(s) announced via the SUSE-SU-2014:0883-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This is a SUSE Linux Enterprise Server 11 SP1 LTSS roll up update of xorg-x11-libXext, fixing a security issue.

These issues require connection to a malicious X server to trigger the bugs in client libraries.

Security issue fixed:

 * CVE-2013-1982: Multiple integer overflows in X.org libXext allowed X
 servers to trigger allocation of insufficient memory and a buffer
 overflow via vectors related to the (1)
XcupGetReservedColormapEntries, (2) XcupStoreColors, (3)
XdbeGetVisualInfo, (4) XeviGetVisualInfo, (5) XShapeGetRectangles, and (6)
XSyncListSystemCounters functions.

Security Issue references:

 * CVE-2013-1982");

  script_tag(name:"affected", value:"'xorg-x11-libXext' package(s) on SUSE Linux Enterprise Server 11 SP1.");

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

if(release == "SLES11.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-libXext", rpm:"xorg-x11-libXext~7.4~1.18.16", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-libXext-32bit", rpm:"xorg-x11-libXext-32bit~7.4~1.18.16", rls:"SLES11.0SP1"))) {
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
