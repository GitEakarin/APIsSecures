using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace APIsSecures.Models
{
    public class LoginModel
    {
        [Required]
        public string User { get; set; }
        [Required]
        public string Pass { get; set; }
        //public string Token { get; set; }
    }
}
