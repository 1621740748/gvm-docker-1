###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for moodle FEDORA-2012-5267
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_xref(name:"URL", value:"http://lists.fedoraproject.org/pipermail/package-announce/2012-April/078210.html");
  script_oid("1.3.6.1.4.1.25623.1.0.864150");
  script_version("2019-11-27T15:23:21+0000");
  script_tag(name:"last_modification", value:"2019-11-27 15:23:21 +0000 (Wed, 27 Nov 2019)");
  script_tag(name:"creation_date", value:"2012-04-13 10:31:25 +0530 (Fri, 13 Apr 2012)");
  script_cve_id("CVE-2012-1155", "CVE-2012-1156", "CVE-2012-1157", "CVE-2012-1158",
                "CVE-2012-1159", "CVE-2012-1160", "CVE-2012-1161", "CVE-2012-1168",
                "CVE-2012-1169", "CVE-2012-1170");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_xref(name:"FEDORA", value:"2012-5267");
  script_name("Fedora Update for moodle FEDORA-2012-5267");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'moodle'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC15");
  script_tag(name:"affected", value:"moodle on Fedora 15");
  script_tag(name:"solution", value:"Please install the updated package(s).");
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

if(release == "FC15")
{

  if ((res = isrpmvuln(pkg:"moodle", rpm:"moodle~1.9.17~1.fc15", rls:"FC15")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
