using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;
using System.Web.Http.Cors;
using Website.EFModel;

namespace Website.Controllers
{
    [Authorize]
    [RoutePrefix("api/Help")]
    [EnableCors(origins: "*", headers: "*", methods: "*")]
    public class HelpController : ApiController
    {
        private WebsiteEntities dbcontext = new WebsiteEntities();

        // GET api/Help/GetCountries
        [HttpGet]
        [AllowAnonymous]
        [Route("GetCountries")]
        public IEnumerable<Country> GetCountries()
        {
            return dbcontext.Countries.ToList();
        }

        
    }
}
