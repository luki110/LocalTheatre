using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web;

namespace LocalTheatreAssessmentLB.Models
{
    public class Staff : User
    {
        [Required]
        [Display(Name = "First Name")]
        public string FirstName { get; set; }
        [Required]
        [Display(Name = "Last Name")]
        public string LastName { get; set; }
        [Required]
        [Display(Name = "Address")]
        public string Address { get; set; }
        [Required]
        [Display(Name = "City")]
        public string City { get; set; }
        [Required]
        [Display(Name = "Date of birth")]
        public DateTime DOB { get; set; }


        public Staff()
        {
            Posts = new List<Post>();
        }
        //navigational properties
        public virtual ICollection<Post> Posts { get; set; }

    }
}