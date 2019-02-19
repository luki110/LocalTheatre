using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Web;

namespace LocalTheatreAssessmentLB.Models
{
    public class Post
    {
        [Key]
        public int PostId { get; set; }
        [Required]
        public string AuthorId { get; set; }
        [Required]
        public string Content { get; set; }
        [Required]
        public string Title { get; set; }
        [Required]
        public DateTime DatePosted { get; set; }
        [Required]
        public bool IsAproved { get; set; }

        public Post()
        {
            Categories = new List<Category>();
        }

        //naviagtional properties
        [ForeignKey("Staff")]
        public string StaffId { get; set; }
        public virtual Staff Staff { get; set; }

        public virtual ICollection<Category> Categories { get; set; }


    }
}