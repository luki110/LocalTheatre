using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web;

namespace LocalTheatreAssessmentLB.Models
{
    public class Category
    {   [Key]
        [Required]
        public int CategoryId { get; set; }
        [Required]
        public string Name { get; set; }

        public Category()
        {
            Posts = new List<Post>();
        }

        //navigational properties
        public virtual ICollection<Post> Posts { get; set; }
    }
}