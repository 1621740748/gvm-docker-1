###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for mediawiki FEDORA-2014-5691
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.867776");
  script_version("2020-02-04T09:04:16+0000");
  script_tag(name:"last_modification", value:"2020-02-04 09:04:16 +0000 (Tue, 04 Feb 2020)");
  script_tag(name:"creation_date", value:"2014-05-12 09:10:21 +0530 (Mon, 12 May 2014)");
  script_cve_id("CVE-2014-2853", "CVE-2014-1610", "CVE-2013-6452", "CVE-2013-6451",
                "CVE-2013-6454", "CVE-2013-6453", "CVE-2013-6472");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Fedora Update for mediawiki FEDORA-2014-5691");
  script_tag(name:"affected", value:"mediawiki on Fedora 19");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"FEDORA", value:"2014-5691");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2014-May/132602.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'mediawiki'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC19");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "FC19")
{

  if ((res = isrpmvuln(pkg:"mediawiki", rpm:"mediawiki~1.21.9~1.fc19", rls:"FC19")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
