###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for xlockmore FEDORA-2012-16490
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
  script_xref(name:"URL", value:"http://lists.fedoraproject.org/pipermail/package-announce/2012-November/091150.html");
  script_oid("1.3.6.1.4.1.25623.1.0.864840");
  script_version("2019-12-10T07:34:00+0000");
  script_tag(name:"last_modification", value:"2019-12-10 07:34:00 +0000 (Tue, 10 Dec 2019)");
  script_tag(name:"creation_date", value:"2012-11-06 17:45:58 +0530 (Tue, 06 Nov 2012)");
  script_cve_id("CVE-2012-4524");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_xref(name:"FEDORA", value:"2012-16490");
  script_name("Fedora Update for xlockmore FEDORA-2012-16490");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'xlockmore'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC16");
  script_tag(name:"affected", value:"xlockmore on Fedora 16");
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

if(release == "FC16")
{

  if ((res = isrpmvuln(pkg:"xlockmore", rpm:"xlockmore~5.40~3.fc16", rls:"FC16")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
