using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace Website.Models
{
    public class HttpResponseModel
    {
        public int Status { get; set; }
        public string Message { get; set; }
        public object Data { get; set; }
    }
}