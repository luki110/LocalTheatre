using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web;

namespace LocalTheatreAssessmentLB.Models
{
    public class Customer : User
    {
        [Required]
        public bool isSuspended { get; set; }


    }
}